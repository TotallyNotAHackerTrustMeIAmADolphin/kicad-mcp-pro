"""Explicit owner invocation never turns Cloud into automatic device access."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from kicad_mcp import cloud_once
from kicad_mcp.cloud_outbound_handshake import CloudHandshakeDeniedError, HandshakeReceipt
from kicad_mcp.cloud_readonly_boundary import LocalReadDeniedError

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Owner-key open is POSIX only")
DEVICE = "11111111-1111-4111-8111-111111111111"
PROJECT = "22222222-2222-4222-8222-222222222222"
SESSION = "33333333-3333-4333-8333-333333333333"
READ = "44444444-4444-4444-8444-444444444444"


def _keyfile(path: Path, *, other: bool = False) -> Path:
    key = (
        generate_private_key(public_exponent=65537, key_size=2048)
        if other
        else Ed25519PrivateKey.generate()
    )
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    path.chmod(0o600)
    return path


def _args(folder: Path, key: Path) -> list[str]:
    return [
        "--cloud-origin",
        "https://cloud.example",
        "--owner-sub",
        "owner-fixture",
        "--device-id",
        DEVICE,
        "--project-id",
        PROJECT,
        "--project-directory",
        str(folder),
        "--filename-stem",
        "demo",
        "--private-key-file",
        str(key),
        "--allow-once",
    ]


def test_no_consent_flag_never_loads_a_key_or_connects(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as denied:
        cloud_once.main(_args(tmp_path, tmp_path / "not-a-key")[:-1])
    assert denied.value.code == 2


def test_owner_only_key_is_loaded_but_weak_or_unsafe_key_is_denied(tmp_path: Path) -> None:
    filename = _keyfile(tmp_path / "private.pem")
    assert isinstance(cloud_once._load_owner_key(filename), Ed25519PrivateKey)
    filename.chmod(0o644)
    with pytest.raises(cloud_once.LocalApprovalDeniedError):
        cloud_once._load_owner_key(filename)
    filename.chmod(0o600)
    link = tmp_path / "link.pem"
    link.symlink_to(filename)
    with pytest.raises(cloud_once.LocalApprovalDeniedError):
        cloud_once._load_owner_key(link)
    with pytest.raises(cloud_once.LocalApprovalDeniedError):
        cloud_once._load_owner_key(tmp_path / "missing.pem")
    filename.write_bytes(b"not a PEM")
    with pytest.raises(cloud_once.LocalApprovalDeniedError):
        cloud_once._load_owner_key(filename)
    filename.write_bytes(b"a" * 9000)
    with pytest.raises(cloud_once.LocalApprovalDeniedError):
        cloud_once._load_owner_key(filename)
    _keyfile(filename, other=True)
    with pytest.raises(cloud_once.LocalApprovalDeniedError):
        cloud_once._load_owner_key(filename)


def test_explicit_approval_uses_only_selected_project_and_file_presence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    folder = tmp_path / "owner-selected"
    folder.mkdir()
    (folder / "demo.kicad_pro").write_text("never send this content")
    keyfile = _keyfile(tmp_path / "enrolled.pem")
    observations: list[str] = []

    async def fake_cloud(**kwargs: object) -> HandshakeReceipt:
        assert kwargs["origin"] == kwargs["trusted_origin"] == "https://cloud.example"
        assert kwargs["owner_sub"] == "owner-fixture"
        assert isinstance(kwargs["signing_key"], Ed25519PrivateKey)
        factory = kwargs["dispatcher_factory"]
        assert callable(factory)
        receipt = HandshakeReceipt(DEVICE, SESSION)
        dispatcher = factory(receipt)
        assert dispatcher._current_authorization() is True
        request = {
            "kind": "connector.read_request",
            "version": 1,
            "deviceId": DEVICE,
            "projectId": PROJECT,
            "requestId": READ,
            "operation": "project_summary",
            "deadlineUnixMs": int(time.time() * 1000) + 1_000,
        }
        result = dispatcher.read(json.dumps(request).encode(), sequence=1)
        observations.append(json.dumps(result))
        dispatcher.close()
        with pytest.raises(LocalReadDeniedError):
            dispatcher.read(json.dumps(request).encode(), sequence=2)
        return receipt

    monkeypatch.setattr(cloud_once, "execute_single_approved_read", fake_cloud)
    assert cloud_once.main(_args(folder, keyfile)) == 0
    assert observations
    assert '"projectPresent": true' in observations[0]
    assert "never send this content" not in observations[0]
    assert str(folder) not in observations[0]
    assert "completed" in capsys.readouterr().out


def test_invalid_local_grant_or_denied_server_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    keyfile = _keyfile(tmp_path / "enrolled.pem")

    async def no_network(**kwargs: object) -> None:
        raise AssertionError("never start TLS without a selected absolute folder")

    monkeypatch.setattr(cloud_once, "execute_single_approved_read", no_network)
    assert cloud_once.main(_args(Path("relative"), keyfile)) == 1
    assert "denied" in capsys.readouterr().err

    async def rejected(**kwargs: object) -> None:
        raise CloudHandshakeDeniedError("handshake denied")

    monkeypatch.setattr(cloud_once, "execute_single_approved_read", rejected)
    assert cloud_once.main(_args(tmp_path, keyfile)) == 1
    assert "denied" in capsys.readouterr().err

    assert cloud_once.main(_args(tmp_path, tmp_path / "missing.pem")) == 1
    assert "denied" in capsys.readouterr().err
