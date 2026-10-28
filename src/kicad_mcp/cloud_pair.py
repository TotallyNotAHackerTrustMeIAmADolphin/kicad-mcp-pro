"""Interactive, explicitly approved Cloud device enrollment (not access enablement).

Initiate the Cloud v1 device challenge with a new or existing owner-only
Ed25519 key, wait for owner approval in a browser, and redeem once. No OAuth
session cookies, bearer tokens, private keys, or local KiCad files are sent.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import ssl
import stat
import sys
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from kicad_mcp.cloud_once import _load_owner_key

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_USER_CODE = re.compile(r"[A-Z0-9]{6}-[A-Z0-9]{6}")
_BASE64URL_32 = re.compile(r"[A-Za-z0-9_-]{43}")
_FINGERPRINT = re.compile(r"[a-f0-9]{64}")


class CloudPairingError(ValueError):
    """Do not leak credentials, internal errors, or private filesystem details."""


def _origin(value: str) -> tuple[str, int, str]:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or not parsed.netloc.isascii()
            or parsed.port == 0
        ):
            raise CloudPairingError("pairing denied")
        port = parsed.port or 443
        host = parsed.hostname
        return host, port, f"https://{parsed.netloc}"
    except ValueError as exc:
        raise CloudPairingError("pairing denied") from exc


def _post(
    origin: tuple[str, int, str], path: str, body: dict[str, object], status: int
) -> dict[str, object]:
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    if len(data) > 1024:
        raise CloudPairingError("pairing denied")
    connection = http.client.HTTPSConnection(
        origin[0], origin[1], timeout=10, context=ssl.create_default_context()
    )
    try:
        connection.request(
            "POST",
            path,
            body=data,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        response = connection.getresponse()
        payload = response.read(2049)
        if (
            response.status != status
            or len(payload) > 2048
            or response.getheader("Content-Type", "").split(";")[0] != "application/json"
        ):
            raise CloudPairingError("pairing denied")
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise CloudPairingError("pairing denied")
        return decoded
    except (OSError, ValueError, http.client.HTTPException, UnicodeError) as exc:
        raise CloudPairingError("pairing denied") from exc
    finally:
        connection.close()


def _create_private_key(path: Path) -> Ed25519PrivateKey:
    """Persist the key before enrollment, so a succeeded redeem cannot lose it."""
    getuid = getattr(os, "getuid", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if (
        os.name != "posix"
        or not callable(getuid)
        or not isinstance(nofollow, int)
        or not path.is_absolute()
    ):
        raise CloudPairingError("pairing denied")
    try:
        parent = path.parent
        if parent.resolve(strict=True) != parent:
            raise CloudPairingError("pairing denied")
        directory = parent.stat()
        if (
            not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != getuid()
            or directory.st_mode & 0o077
        ):
            raise CloudPairingError("pairing denied")
        key = Ed25519PrivateKey.generate()
        data = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        fd = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            # Only this invocation's exclusive newly created private key is removed.
            path.unlink(missing_ok=True)
            raise
        return key
    except (OSError, ValueError) as exc:
        raise CloudPairingError("pairing denied") from exc


def _load_or_create(path: Path) -> Ed25519PrivateKey:
    getuid = getattr(os, "getuid", None)
    if os.name != "posix" or not callable(getuid) or not path.is_absolute():
        raise CloudPairingError("pairing denied")
    try:
        parent = path.parent
        metadata = parent.stat()
        if (
            parent.resolve(strict=True) != parent
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != getuid()
            or metadata.st_mode & 0o077
        ):
            raise CloudPairingError("pairing denied")
    except (OSError, ValueError) as exc:
        raise CloudPairingError("pairing denied") from exc
    if path.is_symlink():
        raise CloudPairingError("pairing denied")
    if path.exists():
        try:
            return _load_owner_key(path)
        except (OSError, ValueError) as exc:
            raise CloudPairingError("pairing denied") from exc
    return _create_private_key(path)


def _challenge(result: dict[str, object], key: Ed25519PrivateKey) -> tuple[str, str, str, str, int]:
    if set(result) != {"challengeId", "userCode", "deviceCode", "deviceFingerprint", "expiresAtMs"}:
        raise CloudPairingError("pairing denied")
    challenge, code, secret, fingerprint, expiry = (
        result["challengeId"],
        result["userCode"],
        result["deviceCode"],
        result["deviceFingerprint"],
        result["expiresAtMs"],
    )
    der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    expected = hashlib.sha256(der).hexdigest()
    if (
        not isinstance(challenge, str)
        or not _UUID.fullmatch(challenge)
        or not isinstance(code, str)
        or not _USER_CODE.fullmatch(code)
        or not isinstance(secret, str)
        or not _BASE64URL_32.fullmatch(secret)
        or not isinstance(fingerprint, str)
        or not _FINGERPRINT.fullmatch(fingerprint)
        or fingerprint != expected
        or type(expiry) is not int
        or not (time.time_ns() // 1_000_000 < expiry <= time.time_ns() // 1_000_000 + 300_000)
    ):
        raise CloudPairingError("pairing denied")
    return challenge, code, secret, fingerprint, expiry


def enroll(
    origin: str, alias: str, keyfile: Path, approval: Callable[[str, str, str], None]
) -> tuple[str, str]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", alias):
        raise CloudPairingError("pairing denied")
    target = _origin(origin)
    key = _load_or_create(keyfile)
    der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    result = _post(
        target,
        "/api/v1/pairing/device/challenge",
        {
            "alias": alias,
            "publicKeyDer": base64.b64encode(der).decode("ascii"),
        },
        201,
    )
    challenge, code, device_secret, fingerprint, expiry = _challenge(result, key)
    approval(target[2] + "/devices/pairing", challenge, code)
    if time.time_ns() // 1_000_000 >= expiry:
        raise CloudPairingError("pairing denied")
    proof = (
        b"kicad-cloud-pairing-proof-v1\x00" + challenge.encode() + b"\x00" + device_secret.encode()
    )
    signature = base64.urlsafe_b64encode(key.sign(proof)).decode("ascii").rstrip("=")
    answer = _post(
        target,
        "/api/v1/pairing/device/redeem",
        {
            "challengeId": challenge,
            "deviceCode": device_secret,
            "signature": signature,
        },
        200,
    )
    if (
        set(answer) != {"deviceId", "deviceFingerprint", "enabled"}
        or not isinstance(answer["deviceId"], str)
        or not _UUID.fullmatch(answer["deviceId"])
        or answer["deviceFingerprint"] != fingerprint
        or answer["enabled"] is not False
    ):
        raise CloudPairingError("pairing denied")
    return answer["deviceId"], fingerprint


def _approval(page: str, challenge: str, code: str) -> None:
    print(f"Open {page} in your signed-in browser; approve challenge {challenge} with code {code}.")
    input("After approving in the browser, press Enter to redeem (Ctrl-C cancels): ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Manually enroll a KiCad Cloud device (disabled by default)"
    )
    parser.add_argument("--cloud-origin", required=True)
    parser.add_argument("--alias", required=True)
    parser.add_argument("--private-key-file", type=Path, required=True)
    parser.add_argument("--begin-pairing", action="store_true", required=True)
    options = parser.parse_args(argv)
    try:
        device_id, fingerprint = enroll(
            options.cloud_origin, options.alias, options.private_key_file, _approval
        )
    except (CloudPairingError, KeyboardInterrupt, EOFError):
        print(
            "Cloud pairing not completed; no access enabled. An owner-only key file may exist.",
            file=sys.stderr,
        )
        return 1
    print(f"Device registered: {device_id}; fingerprint: {fingerprint}; Cloud enabled: false")
    print("No remote access granted. Keep the private key for a future authorized connection.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
