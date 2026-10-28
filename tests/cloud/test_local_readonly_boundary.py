"""Offline contracts for a future connector. No running KiCad or Cloud needed."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from kicad_mcp.cloud_readonly_boundary import (
    LocalReadDeniedError,
    OperatorProject,
    VerifiedLocalBinding,
    inspect_readonly,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason="Secure no-follow directory traversal currently supported on POSIX only",
)

DEVICE = "11111111-1111-4111-8111-111111111111"
PROJECT = "22222222-2222-4222-8222-222222222222"
REQUEST = "33333333-3333-4333-8333-333333333333"
NOW = 1_800_000_000_000
SESSION = "44444444-4444-4444-8444-444444444444"


def bound(
    device: str = DEVICE,
    project: str = PROJECT,
    operations: frozenset[str] = frozenset({"project_summary"}),
    session: str = SESSION,
    expires: int = NOW + 60_000,
) -> VerifiedLocalBinding:
    return VerifiedLocalBinding(device, project, operations, session, expires)


@pytest.fixture
def approved(tmp_path: Path) -> tuple[VerifiedLocalBinding, OperatorProject]:
    folder = tmp_path / "approved"
    folder.mkdir()
    for ext in (".kicad_pro", ".kicad_pcb", ".kicad_sch"):
        (folder / ("Example" + ext)).write_text("confidential content", encoding="utf-8")
    return (
        bound(),
        OperatorProject(DEVICE, PROJECT, folder, "Example"),
    )


def packet(**changes: object) -> bytes:
    frame: dict[str, object] = dict(
        kind="connector.read_request",
        version=1,
        requestId=REQUEST,
        deviceId=DEVICE,
        projectId=PROJECT,
        operation="project_summary",
        deadlineUnixMs=NOW + 1000,
    )
    frame.update(changes)
    return json.dumps(frame, separators=(",", ":")).encode("utf-8")


def invoke(frame: bytes, pair: tuple[VerifiedLocalBinding, OperatorProject]) -> dict[str, object]:
    return inspect_readonly(frame, verified=pair[0], operator_project=pair[1], now_unix_ms=NOW)


def test_approved_metadata_only_no_paths_or_project_contents(approved) -> None:
    result = invoke(packet(), approved)
    assert result == {
        "kind": "connector.local_read_preview",
        "version": 1,
        "requestId": REQUEST,
        "projectId": PROJECT,
        "operation": "project_summary",
        "files": {"projectPresent": True, "boardPresent": True, "schematicPresent": True},
    }
    as_text = json.dumps(result)
    assert "Example" not in as_text
    assert "confidential" not in as_text
    assert str(approved[1].directory) not in as_text


@pytest.mark.parametrize(
    "change",
    [
        {"deviceId": "44444444-4444-4444-8444-444444444444"},
        {"projectId": "55555555-5555-4555-8555-555555555555"},
        {"operation": "run_drc"},
        {"operation": "run_erc"},
        {"operation": ["project_summary"]},
        {"operation": {"name": "project_summary"}},
        {"operation": "write_board"},
        {"operation": "pcb_export"},
        {"deadlineUnixMs": NOW},
        {"deadlineUnixMs": NOW + 30_001},
        {"deadlineUnixMs": NOW + 1.5},
        {"deadlineUnixMs": True},
        {"version": 2},
        {"version": True},
        {"requestId": "../../tmp"},
        {"kind": "device.hello"},
        {"path": "/etc/passwd"},
    ],
)
def test_adversarial_frames_denied(approved, change) -> None:
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(**change), approved)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"{}",
        b"null",
        b"[]",
        b"not-json",
        b"\xff",
        b'{"kind":"connector.read_request","kind":"connector.read_request"}',
        b"x" * 1025,
        packet().replace(b"}", b',"arbitraryKey":"value"}'),
    ],
)
def test_malformed_or_noncanonical_frames_denied(approved, raw) -> None:
    with pytest.raises(LocalReadDeniedError):
        invoke(raw, approved)


def test_untrusted_binding_is_never_accepted(approved) -> None:
    wrong = bound(project="66666666-6666-4666-8666-666666666666")
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), (wrong, approved[1]))
    no_cap = bound(operations=frozenset())
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), (no_cap, approved[1]))


def test_symlinked_folder_and_symlinked_kicad_file_denied(approved, tmp_path) -> None:
    bridge = tmp_path / "link"
    bridge.symlink_to(approved[1].directory, target_is_directory=True)
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), (approved[0], OperatorProject(DEVICE, PROJECT, bridge, "Example")))
    file = approved[1].directory / "Example.kicad_pcb"
    file.unlink()
    file.symlink_to(tmp_path / "private")
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), approved)


def test_symlinked_parent_component_denied(approved, tmp_path) -> None:
    intermediate = tmp_path / "parent_link"
    intermediate.symlink_to(approved[1].directory.parent, target_is_directory=True)
    changed = OperatorProject(DEVICE, PROJECT, intermediate / approved[1].directory.name, "Example")
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), (approved[0], changed))


def test_replaced_file_with_directory_denied(approved) -> None:
    target = approved[1].directory / "Example.kicad_pcb"
    target.unlink()
    target.mkdir()
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), approved)


def test_expired_request_and_invalid_local_context_denied(approved) -> None:
    with pytest.raises(LocalReadDeniedError):
        inspect_readonly(
            packet(), verified=approved[0], operator_project=approved[1], now_unix_ms=NOW + 1000
        )
    bad = OperatorProject("not-a-uuid", PROJECT, approved[1].directory, "Example")
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), (approved[0], bad))


def test_missing_board_is_explicit_and_still_read_only(approved) -> None:
    (approved[1].directory / "Example.kicad_pcb").unlink()
    result = invoke(packet(), approved)
    assert result["files"] == {
        "projectPresent": True,
        "boardPresent": False,
        "schematicPresent": True,
    }


def test_project_path_is_never_from_the_request(approved) -> None:
    with patch("subprocess.run", side_effect=AssertionError("no native process")):
        result = invoke(packet(), approved)
    assert result["operation"] == "project_summary"


def test_directory_entry_budget_denies_surprise_mass_scan(approved) -> None:
    folder = approved[1].directory
    for i in range(130):
        (folder / f"extra-{i}").touch()
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), approved)


def test_relative_operator_path_denied(approved) -> None:
    with pytest.raises(LocalReadDeniedError):
        invoke(
            packet(), (approved[0], OperatorProject(DEVICE, PROJECT, Path("relative"), "Example"))
        )


def test_committed_real_kicad10_sample_metadata_only() -> None:
    root = Path(__file__).resolve().parents[2]
    folder = root / "tests/fixtures/benchmark_projects/pass_minimal_mcu_board"
    assert (folder / "demo.kicad_pro").is_file()
    verified = bound()
    owner_policy = OperatorProject(DEVICE, PROJECT, folder, "demo")
    result = inspect_readonly(
        packet(), verified=verified, operator_project=owner_policy, now_unix_ms=NOW
    )
    assert result["files"] == {
        "projectPresent": True,
        "boardPresent": True,
        "schematicPresent": True,
    }
    assert "demo" not in json.dumps(result)


def test_invalid_operator_filename_type_fails_closed(approved) -> None:
    bad = OperatorProject(DEVICE, PROJECT, approved[1].directory, ["Example"])
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), (approved[0], bad))


@pytest.mark.parametrize(
    "verified",
    [
        bound(session="bad-session"),
        bound(expires=NOW),
        bound(expires=NOW + 300_001),
        bound(expires=True),
        bound(expires=NOW + 500),
    ],
)
def test_session_expiration_and_deadline_bounded(approved, verified) -> None:
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(), (verified, approved[1]))


def test_request_deadline_cannot_outlive_session_lease(approved) -> None:
    valid = bound(expires=NOW + 500)
    assert invoke(packet(deadlineUnixMs=NOW + 200), (valid, approved[1]))["files"]["projectPresent"]
    with pytest.raises(LocalReadDeniedError):
        invoke(packet(deadlineUnixMs=NOW + 1000), (valid, approved[1]))
