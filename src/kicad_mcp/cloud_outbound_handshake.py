"""Explicit opt-in outbound TLS/WebSocket proof handshake for future KiCad Cloud.

This module does not enroll devices, establish OAuth authorization, read files,
dispatch commands or keep a session alive. A completed handshake is NOT a
project-grant or execution capability. It is never started automatically.
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from websockets.asyncio.client import connect
from websockets.exceptions import WebSocketException

from kicad_mcp.cloud_device_proofs import (
    _unique_keys,
    sign_device_challenge,
    sign_session_challenge,
)

CONNECTOR_WS_PATH = "/api/v1/connector/ws"
_DEVICE_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
HANDSHAKE_TIMEOUT_SECONDS = 9


class CloudHandshakeDeniedError(ValueError):
    """Generic failure without leaking server frames or credentials."""


@dataclass(frozen=True)
class HandshakeReceipt:
    """Proof exchange completed; expressly NOT an execution authorization."""

    device_id: str
    session_id: str


def _endpoint(*, origin: str, trusted_origin: str) -> str:
    """Require exact independently configured HTTPS Cloud origin."""
    if not isinstance(origin, str) or not isinstance(trusted_origin, str):
        raise CloudHandshakeDeniedError("handshake denied")
    parsed = urlsplit(origin)
    expected = urlsplit(trusted_origin)
    for item in (parsed, expected):
        if (
            item.scheme != "https"
            or not item.hostname
            or item.username is not None
            or item.password is not None
            or item.path not in ("", "/")
            or item.query
            or item.fragment
            or item.hostname.endswith(".")
        ):
            raise CloudHandshakeDeniedError("handshake denied")
        try:
            if item.port is not None and not (1 <= item.port <= 65535):
                raise CloudHandshakeDeniedError("handshake denied")
        except ValueError as exc:
            raise CloudHandshakeDeniedError("handshake denied") from exc
    if origin != trusted_origin or not origin.startswith("https://"):
        raise CloudHandshakeDeniedError("handshake denied")
    # Use the checked original URL with a scheme swap; it cannot contain
    # embedded credentials, redirects, query parameters or another path.
    return "wss://" + origin[len("https://") :].rstrip("/") + CONNECTOR_WS_PATH


def _read_strict_json(raw: str, expected_kind: str) -> dict[str, object]:
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > 1024:
        raise CloudHandshakeDeniedError("handshake denied")
    try:
        message = json.loads(raw, object_pairs_hook=_unique_keys)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise CloudHandshakeDeniedError("handshake denied") from exc
    if not isinstance(message, dict) or message.get("kind") != expected_kind:
        raise CloudHandshakeDeniedError("handshake denied")
    return message


async def establish_proof_only_handshake(
    *,
    origin: str,
    trusted_origin: str,
    owner_sub: str,
    device_id: str,
    signing_key: Ed25519PrivateKey,
    tls_context: ssl.SSLContext | None = None,
) -> HandshakeReceipt:
    """Perform the real Cloud v1 proof order and immediately close the socket.

    Origin and credentials MUST come from independently trusted operator setup
    (not Cloud messages). A custom TLS context is for controlled enterprise
    trust roots or isolated tests; disabling certificate/hostname verification
    is forbidden. No on-disk key management or actual KiCad project reads.
    """
    endpoint = _endpoint(origin=origin, trusted_origin=trusted_origin)
    if (
        not isinstance(owner_sub, str)
        or not (1 <= len(owner_sub) <= 256)
        or owner_sub != owner_sub.strip()
        or not isinstance(device_id, str)
        or _DEVICE_UUID.fullmatch(device_id) is None
        or not isinstance(signing_key, Ed25519PrivateKey)
    ):
        raise CloudHandshakeDeniedError("handshake denied")
    context = tls_context if tls_context is not None else ssl.create_default_context()
    if (
        not isinstance(context, ssl.SSLContext)
        or context.verify_mode != ssl.CERT_REQUIRED
        or not context.check_hostname
    ):
        raise CloudHandshakeDeniedError("handshake denied")

    def now_ms() -> int:
        return int(datetime.now(UTC).timestamp() * 1000)

    try:
        async with asyncio.timeout(HANDSHAKE_TIMEOUT_SECONDS):
            async with connect(
                endpoint,
                ssl=context,
                origin=None,
                compression=None,
                max_size=1024,
                max_queue=2,
                open_timeout=3,
                close_timeout=2,
            ) as socket:
                if socket.transport.get_extra_info("ssl_object") is None:
                    raise CloudHandshakeDeniedError("handshake denied")
                await socket.send(
                    json.dumps(
                        {
                            "kind": "device.hello",
                            "version": 1,
                            "ownerSub": owner_sub,
                            "deviceId": device_id,
                        },
                        separators=(",", ":"),
                    )
                )
                challenge = await socket.recv()
                if not isinstance(challenge, str):
                    raise CloudHandshakeDeniedError("handshake denied")
                proof = sign_device_challenge(
                    challenge.encode(),
                    expected_device_id=device_id,
                    now_unix_ms=now_ms(),
                    signing_key=signing_key,
                )
                await socket.send(json.dumps(proof, separators=(",", ":")))
                session = await socket.recv()
                if not isinstance(session, str):
                    raise CloudHandshakeDeniedError("handshake denied")
                signed = sign_session_challenge(
                    session.encode(),
                    expected_device_id=device_id,
                    now_unix_ms=now_ms(),
                    signing_key=signing_key,
                )
                accepted_session = _read_strict_json(session, "connector.session_challenge")
                session_id = accepted_session["sessionId"]
                if not isinstance(session_id, str):
                    raise CloudHandshakeDeniedError("handshake denied")
                await socket.send(json.dumps(signed, separators=(",", ":")))
                raw_ready = await socket.recv()
                if not isinstance(raw_ready, str):
                    raise CloudHandshakeDeniedError("handshake denied")
                ready = _read_strict_json(raw_ready, "connector.ready")
                if (
                    set(ready) != {"kind", "version"}
                    or type(ready["version"]) is not int
                    or ready["version"] != 1
                ):
                    raise CloudHandshakeDeniedError("handshake denied")
                # Do not dispatch remote commands. Socket is explicitly closed
                # by exiting this context immediately after the handshake.
                return HandshakeReceipt(device_id=device_id, session_id=session_id)
    except (OSError, ValueError, TimeoutError, WebSocketException) as exc:
        raise CloudHandshakeDeniedError("handshake denied") from exc
