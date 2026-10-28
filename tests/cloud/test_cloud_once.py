"""Explicit owner invocation never turns Cloud into automatic device access."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

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
    if not other:
        from kicad_mcp.cloud_pair import _save_owner_binding

        der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        _save_owner_binding(
            path,
            origin="https://cloud.example",
            device_id=DEVICE,
            fingerprint=hashlib.sha256(der).hexdigest(),
        )
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
    _raise_argument_1 = _args(tmp_path, tmp_path / "not-a-key")[:-1]
    with pytest.raises(SystemExit) as denied:
        cloud_once.main(_raise_argument_1)
    assert denied.value.code == 2


def test_terminal_consent_rejects_noninteractive_or_declined_requests(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    options = argparse.Namespace(
        cloud_origin="https://cloud.example",
        owner_sub="owner-fixture",
        device_id=DEVICE,
        project_id=PROJECT,
        project_directory=tmp_path,
        filename_stem="demo",
        private_key_file=tmp_path / "owner.pem",
    )
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("no prompt for piped commands"))
    with pytest.raises(cloud_once.LocalApprovalDeniedError):
        cloud_once._confirm_local_read(options)


def test_unbound_owner_key_denied_before_private_key_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    keyfile = _keyfile(tmp_path / "unbound.pem")
    keyfile.with_name(keyfile.name + ".cloud-binding-v1.json").unlink()
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: "APPROVE CAFEBABE")
    monkeypatch.setattr(cloud_once.secrets, "token_hex", lambda _: "cafebabe")
    monkeypatch.setattr(
        cloud_once,
        "execute_single_approved_read",
        lambda **_: pytest.fail("unpaired key must never connect"),
    )
    assert cloud_once.main(_args(tmp_path, keyfile)) == 1
    assert "denied" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("--cloud-origin", "https://wrong.example"),
        ("--device-id", "55555555-5555-4555-8555-555555555555"),
    ],
)
def test_enrollment_pin_denies_another_cloud_or_device_before_key_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    override: str,
    value: str,
) -> None:
    keyfile = _keyfile(tmp_path / "enrolled.pem")
    args = _args(tmp_path, keyfile)
    args[args.index(override) + 1] = value
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: "APPROVE CAFEBABE")
    monkeypatch.setattr(cloud_once.secrets, "token_hex", lambda _: "cafebabe")
    monkeypatch.setattr(cloud_once, "_load_owner_key", lambda *_: pytest.fail("do not open key"))
    monkeypatch.setattr(
        cloud_once,
        "execute_single_approved_read",
        lambda **_: pytest.fail("never connect to a substituted origin/device"),
    )
    assert cloud_once.main(args) == 1
    assert "denied" in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["symlink", "world-readable", "duplicate-json", "mismatch"])
def test_enrollment_pin_rejects_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    keyfile = _keyfile(tmp_path / "enrolled.pem")
    binding = keyfile.with_name(keyfile.name + ".cloud-binding-v1.json")
    if kind == "symlink":
        copy = tmp_path / "copy.json"
        copy.write_bytes(binding.read_bytes())
        binding.unlink()
        binding.symlink_to(copy)
    elif kind == "world-readable":
        binding.chmod(0o644)
    elif kind == "duplicate-json":
        binding.write_text('{"origin":"https://cloud.example","origin":"https://other.example"}')
    else:
        value = json.loads(binding.read_text())
        value["fingerprint"] = "0" * 64
        binding.write_text(json.dumps(value))
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: "APPROVE CAFEBABE")
    monkeypatch.setattr(cloud_once.secrets, "token_hex", lambda _: "cafebabe")
    monkeypatch.setattr(
        cloud_once,
        "execute_single_approved_read",
        lambda **_: pytest.fail("invalid enrollment pin must not connect"),
    )
    assert cloud_once.main(_args(tmp_path, keyfile)) == 1
    assert "denied" in capsys.readouterr().err


def test_piped_cli_denied_before_private_key_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: False)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: False)
    monkeypatch.setattr("builtins.input", lambda *_: pytest.fail("must not prompt"))
    monkeypatch.setattr(
        cloud_once, "_load_owner_key", lambda *_: pytest.fail("denied before private key read")
    )
    monkeypatch.setattr(
        cloud_once,
        "execute_single_approved_read",
        lambda **_: pytest.fail("denied before any outbound connection"),
    )
    assert cloud_once.main(_args(tmp_path, tmp_path / "unavailable.pem")) == 1
    assert "denied" in capsys.readouterr().err


@pytest.mark.parametrize("reason", [EOFError, KeyboardInterrupt])
def test_aborted_terminal_confirmation_never_reads_owner_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: type[BaseException],
) -> None:
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: (_ for _ in ()).throw(reason()))
    monkeypatch.setattr(
        cloud_once, "_load_owner_key", lambda *_: pytest.fail("key must stay unopened")
    )
    assert cloud_once.main(_args(tmp_path, tmp_path / "missing.pem")) == 1


def test_terminal_consent_requires_fresh_explicit_challenge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    options = argparse.Namespace(
        cloud_origin="https://cloud.example",
        owner_sub="owner-fixture",
        device_id=DEVICE,
        project_id=PROJECT,
        project_directory=tmp_path,
        filename_stem="demo",
        private_key_file=tmp_path / "owner.pem",
    )
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.secrets, "token_hex", lambda _: "cafebabe")
    responses = iter(["APPROVE expired", "APPROVE CAFEBABE"])
    monkeypatch.setattr("builtins.input", lambda *_: next(responses))
    with pytest.raises(cloud_once.LocalApprovalDeniedError):
        cloud_once._confirm_local_read(options)
    cloud_once._confirm_local_read(options)
    terminal = capsys.readouterr().out
    assert repr(str(options.project_directory)) in terminal
    displayed_lines = terminal.splitlines()
    assert f"Cloud origin: {options.cloud_origin!r}" in displayed_lines
    assert f"Project UUID: {options.project_id!r}" in displayed_lines
    assert f"Owner account: {options.owner_sub!r}" in displayed_lines
    assert f"Device UUID: {options.device_id!r}" in displayed_lines
    assert f"Owner key file: {str(options.private_key_file)!r}" in displayed_lines


def test_terminal_consent_declined_cannot_access_private_key_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.secrets, "token_hex", lambda _: "1234abcd")
    monkeypatch.setattr("builtins.input", lambda *_: "APPROVE wrong")
    monkeypatch.setattr(
        cloud_once, "_load_owner_key", lambda *_: pytest.fail("denied before key read")
    )
    monkeypatch.setattr(
        cloud_once,
        "execute_single_approved_read",
        lambda **_: pytest.fail("denied before network"),
    )
    assert cloud_once.main(_args(tmp_path, tmp_path / "unavailable.pem")) == 1
    assert "denied" in capsys.readouterr().err


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
        _raise_argument_2 = json.dumps(request).encode()
        with pytest.raises(LocalReadDeniedError):
            dispatcher.read(_raise_argument_2, sequence=2)
        return receipt

    monkeypatch.setattr(cloud_once, "execute_single_approved_read", fake_cloud)
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.secrets, "token_hex", lambda _: "cafebabe")
    monkeypatch.setattr("builtins.input", lambda *_: "APPROVE CAFEBABE")
    assert cloud_once.main(_args(folder, keyfile)) == 0
    assert observations
    assert '"projectPresent": true' in observations[0]
    assert "never send this content" not in observations[0]
    assert str(folder) not in observations[0]
    assert "completed" in capsys.readouterr().out


def test_local_lease_expires_on_monotonic_clock_even_if_wall_clock_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "selected"
    folder.mkdir()
    (folder / "demo.kicad_pro").touch()
    keyfile = _keyfile(tmp_path / "enrolled.pem")
    clock = {"wall_ms": 1_800_000_000_000, "monotonic_ns": 100_000_000_000}
    monkeypatch.setattr(cloud_once.time, "time_ns", lambda: clock["wall_ms"] * 1_000_000)
    monkeypatch.setattr(cloud_once.time, "monotonic_ns", lambda: clock["monotonic_ns"])

    async def fake_cloud(**kwargs: object) -> HandshakeReceipt:
        factory = kwargs["dispatcher_factory"]
        assert callable(factory)
        receipt = HandshakeReceipt(DEVICE, SESSION)
        dispatcher = factory(receipt)

        def frame(request_id: str) -> bytes:
            return json.dumps(
                {
                    "kind": "connector.read_request",
                    "version": 1,
                    "deviceId": DEVICE,
                    "projectId": PROJECT,
                    "requestId": request_id,
                    "operation": "project_summary",
                    "deadlineUnixMs": clock["wall_ms"] + 1000,
                }
            ).encode()

        clock["wall_ms"] -= 5_000
        clock["monotonic_ns"] += 29_000_000_000
        assert dispatcher._current_authorization() is True
        assert dispatcher.read(frame(READ), sequence=1)["files"]["projectPresent"] is True
        clock["monotonic_ns"] += 1_000_000_000
        assert dispatcher._current_authorization() is False
        with pytest.raises(LocalReadDeniedError):
            dispatcher.read(frame("66666666-6666-4666-8666-666666666666"), sequence=2)
        dispatcher.close()
        return receipt

    monkeypatch.setattr(cloud_once, "execute_single_approved_read", fake_cloud)
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: "APPROVE CAFEBABE")
    monkeypatch.setattr(cloud_once.secrets, "token_hex", lambda _: "cafebabe")
    assert cloud_once.main(_args(folder, keyfile)) == 0


def test_one_shot_cli_grant_rejects_second_read_even_when_lease_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "selected"
    folder.mkdir()
    (folder / "demo.kicad_pro").touch()
    keyfile = _keyfile(tmp_path / "enrolled.pem")

    async def fake_cloud(**kwargs: object) -> HandshakeReceipt:
        factory = kwargs["dispatcher_factory"]
        assert callable(factory)
        receipt = HandshakeReceipt(DEVICE, SESSION)
        dispatcher = factory(receipt)
        deadline = int(time.time() * 1000) + 1000

        def frame(request_id: str) -> bytes:
            return json.dumps(
                {
                    "kind": "connector.read_request",
                    "version": 1,
                    "deviceId": DEVICE,
                    "projectId": PROJECT,
                    "requestId": request_id,
                    "operation": "project_summary",
                    "deadlineUnixMs": deadline,
                }
            ).encode()

        assert dispatcher.read(frame(READ), sequence=1)["files"]["projectPresent"] is True
        assert dispatcher._current_authorization() is True
        with pytest.raises(LocalReadDeniedError):
            dispatcher.read(frame("55555555-5555-4555-8555-555555555555"), sequence=2)
        dispatcher.close()
        return receipt

    monkeypatch.setattr(cloud_once, "execute_single_approved_read", fake_cloud)
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: "APPROVE CAFEBABE")
    monkeypatch.setattr(cloud_once.secrets, "token_hex", lambda _: "cafebabe")
    assert cloud_once.main(_args(folder, keyfile)) == 0


def test_invalid_local_grant_or_denied_server_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    keyfile = _keyfile(tmp_path / "enrolled.pem")

    async def no_network(**kwargs: object) -> None:
        raise AssertionError("never start TLS without a selected absolute folder")

    monkeypatch.setattr(cloud_once, "execute_single_approved_read", no_network)
    monkeypatch.setattr(cloud_once.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(cloud_once.secrets, "token_hex", lambda _: "cafebabe")
    monkeypatch.setattr("builtins.input", lambda *_: "APPROVE CAFEBABE")
    assert cloud_once.main(_args(Path("relative"), keyfile)) == 1
    assert "denied" in capsys.readouterr().err

    async def rejected(**kwargs: object) -> None:
        raise CloudHandshakeDeniedError("handshake denied")

    monkeypatch.setattr(cloud_once, "execute_single_approved_read", rejected)
    assert cloud_once.main(_args(tmp_path, keyfile)) == 1
    assert "denied" in capsys.readouterr().err

    assert cloud_once.main(_args(tmp_path, tmp_path / "missing.pem")) == 1
    assert "denied" in capsys.readouterr().err
