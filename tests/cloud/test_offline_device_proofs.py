"""Byte-exact Ed25519 proof parity with Cloud v1 TS domain-separated messages.

Only synthetic, ephemeral in-memory keys; no network, owner credentials, keys
on disk, GUI service, device enrollment or connector WebSocket is involved.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kicad_mcp.cloud_device_proofs import (
    OfflineProofDeniedError,
    sign_device_challenge,
    sign_session_challenge,
)

DEVICE = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
CHALLENGE = "33333333-3333-4333-8333-333333333333"
SESSION = "44444444-4444-4444-8444-444444444444"
NOW = 1_800_000_000_000
NONCE = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
BINDING = base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("=")


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def packet(kind: str = "device.challenge", **changes: object) -> bytes:
    body: dict[str, object] = {
        "kind": kind,
        "version": 1,
        "challengeId": CHALLENGE,
        "deviceId": DEVICE,
        "nonce": NONCE,
        "expiresAtMs": NOW + 35_000,
    }
    if kind == "connector.session_challenge":
        body.update(sessionId=SESSION, binding=BINDING)
    body.update(changes)
    return json.dumps(body, separators=(",", ":")).encode()


def signature_bytes(proof: dict[str, object]) -> bytes:
    value = proof["signature"]
    assert isinstance(value, str)
    assert len(value) == 86
    return base64.urlsafe_b64decode(value + "==")


def test_device_proof_matches_cloud_domain_separation(key: Ed25519PrivateKey) -> None:
    response = sign_device_challenge(
        packet(), expected_device_id=DEVICE, now_unix_ms=NOW, signing_key=key
    )
    assert response["kind"] == "device.proof"
    assert response["version"] == 1
    # Exact Cloud src/device-handshake.ts deviceHandshakeProof string/byte order.
    expected = (
        b"kicad-cloud-device-handshake-v1\0"
        + CHALLENGE.encode()
        + b"\0"
        + DEVICE.encode()
        + b"\0"
        + NONCE.encode()
    )
    key.public_key().verify(signature_bytes(response), expected)
    with pytest.raises(InvalidSignature):
        key.public_key().verify(signature_bytes(response), expected + b"changed")


def test_session_proof_matches_cloud_domain_separation(key: Ed25519PrivateKey) -> None:
    response = sign_session_challenge(
        packet("connector.session_challenge"),
        expected_device_id=DEVICE,
        now_unix_ms=NOW,
        signing_key=key,
    )
    assert response["kind"] == "connector.session_proof"
    # Exact Cloud src/connector-session.ts connectorSessionProof byte order.
    expected = (
        b"kicad-cloud-bound-session-v1\0"
        + SESSION.encode()
        + b"\0"
        + CHALLENGE.encode()
        + b"\0"
        + DEVICE.encode()
        + b"\0"
        + NONCE.encode()
        + b"\0"
        + BINDING.encode()
    )
    key.public_key().verify(signature_bytes(response), expected)
    for modified in (
        expected.replace(SESSION.encode(), OTHER.encode()),
        expected.replace(BINDING.encode(), NONCE.encode()),
        expected.replace(DEVICE.encode(), OTHER.encode()),
        b"kicad-cloud-device-handshake-v1\0" + expected,
    ):
        with pytest.raises(InvalidSignature):
            key.public_key().verify(signature_bytes(response), modified)


@pytest.mark.parametrize(
    "change",
    [
        {"deviceId": OTHER},
        {"version": True},
        {"version": 2},
        {"nonce": "not-a-nonce"},
        {"nonce": NONCE[:-1] + "="},
        {"challengeId": "untrusted"},
        {"expiresAtMs": NOW},
        {"expiresAtMs": NOW + 60_001},
        {"expiresAtMs": True},
        {"expiresAtMs": NOW + 1.5},
        {"path": "/home/user/project"},
    ],
)
def test_bad_device_challenge_fails_without_signing(
    key: Ed25519PrivateKey, change: dict[str, object]
) -> None:
    with pytest.raises(OfflineProofDeniedError):
        sign_device_challenge(
            packet(**change), expected_device_id=DEVICE, now_unix_ms=NOW, signing_key=key
        )


@pytest.mark.parametrize(
    "change",
    [
        {"deviceId": OTHER},
        {"sessionId": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
        {"sessionId": "untrusted"},
        {"binding": "short"},
        {"binding": NONCE[:-1] + "="},
        {"nonce": "not-a-nonce"},
        {"expiresAtMs": NOW - 1},
        {"expiresAtMs": NOW + 99_000},
        {"ownerSub": "untrusted-owner"},
    ],
)
def test_bad_session_challenge_fails_without_signing(
    key: Ed25519PrivateKey, change: dict[str, object]
) -> None:
    with pytest.raises(OfflineProofDeniedError):
        sign_session_challenge(
            packet("connector.session_challenge", **change),
            expected_device_id=DEVICE,
            now_unix_ms=NOW,
            signing_key=key,
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{}",
        b"null",
        b"[]",
        b"invalid",
        b"\xff",
        b'{"kind":"device.challenge","kind":"device.challenge"}',
        b"x" * 1025,
    ],
)
def test_invalid_raw_payloads_deny(raw: bytes, key: Ed25519PrivateKey) -> None:
    with pytest.raises(OfflineProofDeniedError):
        sign_device_challenge(raw, expected_device_id=DEVICE, now_unix_ms=NOW, signing_key=key)


def test_proof_is_bound_to_key_identity(key: Ed25519PrivateKey) -> None:
    signed = sign_device_challenge(
        packet(), expected_device_id=DEVICE, now_unix_ms=NOW, signing_key=key
    )
    other = Ed25519PrivateKey.generate()
    expected = (
        b"kicad-cloud-device-handshake-v1\0"
        + CHALLENGE.encode()
        + b"\0"
        + (DEVICE + "\0" + NONCE).encode()
    )
    with pytest.raises(InvalidSignature):
        other.public_key().verify(signature_bytes(signed), expected)


def test_device_session_signatures_do_not_reuse_same_domain(key: Ed25519PrivateKey) -> None:
    first = sign_device_challenge(
        packet(), expected_device_id=DEVICE, now_unix_ms=NOW, signing_key=key
    )
    second = sign_session_challenge(
        packet("connector.session_challenge"),
        expected_device_id=DEVICE,
        now_unix_ms=NOW,
        signing_key=key,
    )
    assert first["signature"] != second["signature"]


def test_does_not_use_disk_or_network_for_signing(
    key: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pathlib import Path

    def prohibited(*_: object, **__: object) -> None:
        raise AssertionError("unexpected file or network operation")

    monkeypatch.setattr("socket.socket.connect", prohibited)
    monkeypatch.setattr(Path, "write_bytes", prohibited)
    assert (
        sign_device_challenge(
            packet(), expected_device_id=DEVICE, now_unix_ms=NOW, signing_key=key
        )["kind"]
        == "device.proof"
    )


def test_spki_public_key_format_matches_cloud_credential_verifier(
    key: Ed25519PrivateKey,
) -> None:
    # Cloud's device handshake stores SPKI DER and uses createPublicKey
    # with format="der", type="spki" before verifying 64-byte Ed25519.
    from cryptography.hazmat.primitives import serialization

    der = key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    loaded = serialization.load_der_public_key(der)
    assert isinstance(loaded, type(key.public_key()))
    proof = sign_session_challenge(
        packet("connector.session_challenge"),
        expected_device_id=DEVICE,
        now_unix_ms=NOW,
        signing_key=key,
    )
    cloud_message = (
        b"kicad-cloud-bound-session-v1\0"
        + SESSION.encode()
        + b"\0"
        + CHALLENGE.encode()
        + b"\0"
        + DEVICE.encode()
        + b"\0"
        + NONCE.encode()
        + b"\0"
        + BINDING.encode()
    )
    loaded.verify(signature_bytes(proof), cloud_message)


def test_invalid_private_key_reference_refused_before_signing() -> None:
    with pytest.raises(OfflineProofDeniedError):
        sign_device_challenge(
            packet(),
            expected_device_id=DEVICE,
            now_unix_ms=NOW,
            signing_key=object(),  # type: ignore[arg-type]
        )
