"""Real opt-in client, synthetic localhost TLS and Ed25519 Cloud proof peer."""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_isolated_tls_websocket_handshake import _synthetic_tls
from websockets.asyncio.server import ServerConnection, serve

from kicad_mcp.cloud_outbound_handshake import (
    CloudHandshakeDeniedError,
    establish_proof_only_handshake,
)

DEVICE = "11111111-1111-4111-8111-111111111111"
OTHER_DEVICE = "22222222-2222-4222-8222-222222222222"
CHALLENGE = "33333333-3333-4333-8333-333333333333"
SESSION = "44444444-4444-4444-8444-444444444444"
SESSION_CHALLENGE = "55555555-5555-4555-8555-555555555555"
OWNER = "fixture-owner"
NONCE = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
BINDING = base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("=")


def _sig(reply: dict[str, object]) -> bytes:
    value = reply.get("signature")
    assert isinstance(value, str)
    return base64.urlsafe_b64decode(value + "==")


async def _scenario(tmp_path: Path, mode: str = "success") -> list[str]:
    tls, pem = _synthetic_tls(tmp_path)
    signing_key = Ed25519PrivateKey.generate()
    observations: list[str] = []

    async def peer(ws: ServerConnection) -> None:
        try:
            hello = json.loads(await ws.recv())
            assert hello == {
                "kind": "device.hello",
                "version": 1,
                "ownerSub": OWNER,
                "deviceId": DEVICE,
            }
            observations.append("hello")
            expiry = int(datetime.now(UTC).timestamp() * 1000) + 30_000
            if mode == "premature-ready":
                await ws.send('{"kind":"connector.ready","version":1}')
                return
            await ws.send(
                json.dumps(
                    {
                        "kind": "device.challenge",
                        "version": 1,
                        "challengeId": CHALLENGE,
                        "deviceId": OTHER_DEVICE if mode == "wrong-device" else DEVICE,
                        "nonce": NONCE,
                        "expiresAtMs": expiry,
                    }
                )
            )
            proof = json.loads(await ws.recv())
            signing_key.public_key().verify(
                _sig(proof),
                b"kicad-cloud-device-handshake-v1\0"
                + CHALLENGE.encode()
                + b"\0"
                + DEVICE.encode()
                + b"\0"
                + NONCE.encode(),
            )
            observations.append("device_verified")
            await ws.send(
                json.dumps(
                    {
                        "kind": "connector.session_challenge",
                        "version": 1,
                        "challengeId": SESSION_CHALLENGE,
                        "deviceId": DEVICE,
                        "sessionId": SESSION,
                        "nonce": NONCE,
                        "binding": BINDING,
                        "expiresAtMs": expiry,
                    }
                )
            )
            second = json.loads(await ws.recv())
            signing_key.public_key().verify(
                _sig(second),
                b"kicad-cloud-bound-session-v1\0"
                + SESSION.encode()
                + b"\0"
                + SESSION_CHALLENGE.encode()
                + b"\0"
                + DEVICE.encode()
                + b"\0"
                + NONCE.encode()
                + b"\0"
                + BINDING.encode(),
            )
            observations.append("session_verified")
            if mode == "bad-ready":
                await ws.send('{"kind":"connector.ready","version":2}')
            else:
                await ws.send('{"kind":"connector.ready","version":1}')
        except Exception:
            return

    async with serve(peer, "127.0.0.1", 0, ssl=tls) as server:
        assert server.sockets
        port = server.sockets[0].getsockname()[1]
        origin = f"https://localhost:{port}"
        trust = ssl.create_default_context(cadata=pem)
        if mode == "untrusted-ca":
            trust = ssl.create_default_context()
        if mode == "wrong-host":
            origin = f"https://127.0.0.1:{port}"
        try:
            receipt = await establish_proof_only_handshake(
                origin=origin,
                trusted_origin=origin,
                owner_sub=OWNER,
                device_id=DEVICE,
                signing_key=signing_key,
                tls_context=trust,
            )
        except CloudHandshakeDeniedError:
            if mode == "success":
                raise
            observations.append("denied")
        else:
            assert mode == "success", "a negative scenario was admitted"
            assert receipt.device_id == DEVICE and receipt.session_id == SESSION
            observations.append("completed")
    return observations


def test_secure_opt_in_real_wss_exchange(tmp_path: Path) -> None:
    assert asyncio.run(_scenario(tmp_path)) == [
        "hello",
        "device_verified",
        "session_verified",
        "completed",
    ]


@pytest.mark.parametrize(
    "mode",
    ["untrusted-ca", "wrong-host", "wrong-device", "premature-ready", "bad-ready"],
)
def test_security_denies_without_unsafe_fallback(tmp_path: Path, mode: str) -> None:
    got = asyncio.run(_scenario(tmp_path, mode))
    assert got[-1] == "denied"
    if mode in ("untrusted-ca", "wrong-host"):
        assert got == ["denied"], "TLS must verify before any secret-key signing"
    if mode in ("wrong-device", "premature-ready"):
        assert "device_verified" not in got


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:443",
        "ws://localhost:443",
        "wss://localhost:443/api/v1/connector/ws",
        "https://example.com:443/not-allowed",
        "https://user@localhost:443",
        "https://localhost:443/?secret",
        "https://localhost:443/#fragment",
        "https://localhost:443",
    ],
)
def test_refuse_untrusted_or_malformed_origin_before_network(origin: str) -> None:
    with pytest.raises(CloudHandshakeDeniedError):
        asyncio.run(
            establish_proof_only_handshake(
                origin=origin,
                trusted_origin="https://localhost:444",
                owner_sub=OWNER,
                device_id=DEVICE,
                signing_key=Ed25519PrivateKey.generate(),
            )
        )


def test_no_trust_verification_optout_even_for_localhost() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(CloudHandshakeDeniedError):
        asyncio.run(
            establish_proof_only_handshake(
                origin="https://localhost:445",
                trusted_origin="https://localhost:445",
                owner_sub=OWNER,
                device_id=DEVICE,
                signing_key=Ed25519PrivateKey.generate(),
                tls_context=context,
            )
        )


@pytest.mark.parametrize(
    ("owner", "device"),
    [
        ("", DEVICE),
        ("  ", DEVICE),
        ("wrong-owner ", DEVICE),
        ("x" * 257, DEVICE),
        (OWNER, "bogus-device"),
        (OWNER, DEVICE.upper()),
    ],
)
def test_refuse_invalid_local_identity_before_network(owner: str, device: str) -> None:
    with pytest.raises(CloudHandshakeDeniedError):
        asyncio.run(
            establish_proof_only_handshake(
                origin="https://localhost:445",
                trusted_origin="https://localhost:445",
                owner_sub=owner,
                device_id=device,
                signing_key=Ed25519PrivateKey.generate(),
            )
        )
