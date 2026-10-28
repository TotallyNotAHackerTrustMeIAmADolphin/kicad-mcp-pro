"""Manual, one-shot Cloud project-presence connector; never auto-started.

The owner must explicitly choose a project and an already enrolled device key.
No pairing, OAuth authorization, device registration, filesystem discovery,
KiCad execution or background service is created by this command. The Cloud
server independently verifies its live OAuth client/project grant.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import stat
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from kicad_mcp.cloud_outbound_handshake import (
    CloudHandshakeDeniedError,
    HandshakeReceipt,
    execute_single_approved_read,
)
from kicad_mcp.cloud_read_dispatch import LocalReadDispatch
from kicad_mcp.cloud_readonly_boundary import OperatorProject, VerifiedLocalBinding


class LocalApprovalDeniedError(ValueError):
    """Fail closed, without returning private-key or filesystem details."""


def _load_owner_key(filename: Path) -> Ed25519PrivateKey:
    """Read a regular owner-only PEM through a non-following file descriptor."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if os.name != "posix" or not isinstance(nofollow, int):
        raise LocalApprovalDeniedError("local approval denied")
    descriptor: int | None = None
    try:
        descriptor = os.open(filename, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
            or not 1 <= metadata.st_size <= 8192
        ):
            raise LocalApprovalDeniedError("local approval denied")
        key = load_pem_private_key(os.read(descriptor, 8193), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise LocalApprovalDeniedError("local approval denied")
        return key
    except (OSError, ValueError, TypeError) as exc:
        raise LocalApprovalDeniedError("local approval denied") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="One approved KiCad Cloud metadata read")
    parser.add_argument("--cloud-origin", required=True, help="Trusted HTTPS origin chosen locally")
    parser.add_argument("--owner-sub", required=True, help="Enrolled account subject")
    parser.add_argument("--device-id", required=True, help="Already enrolled device UUID")
    parser.add_argument("--project-id", required=True, help="Explicitly allowed project UUID")
    parser.add_argument(
        "--project-directory", type=Path, required=True, help="Approved absolute folder"
    )
    parser.add_argument("--filename-stem", required=True, help="Approved direct-child project stem")
    parser.add_argument(
        "--private-key-file", type=Path, required=True, help="Owner-only Ed25519 PEM"
    )
    parser.add_argument(
        "--allow-once",
        action="store_true",
        required=True,
        help="Explicit local consent; one presence-only read, no native operation",
    )
    return parser


async def _connect(options: argparse.Namespace) -> HandshakeReceipt:
    if not options.allow_once or not options.project_directory.is_absolute():
        raise LocalApprovalDeniedError("local approval denied")
    signing_key = _load_owner_key(options.private_key_file)

    def approved_local_project(receipt: HandshakeReceipt) -> LocalReadDispatch:
        # This is an independent, local, time-limited operator grant, never a
        # Cloud-supplied authorization flag or a synthetic always-true grant.
        cutoff = time.time_ns() // 1_000_000 + 30_000
        return LocalReadDispatch(
            verified=VerifiedLocalBinding(
                device_id=receipt.device_id,
                project_id=options.project_id,
                operations=frozenset({"project_summary"}),
                session_id=receipt.session_id,
                session_expires_unix_ms=cutoff,
            ),
            operator_project=OperatorProject(
                device_id=options.device_id,
                project_id=options.project_id,
                directory=options.project_directory,
                filename_stem=options.filename_stem,
            ),
            current_authorization=lambda: time.time_ns() // 1_000_000 < cutoff,
        )

    return await execute_single_approved_read(
        origin=options.cloud_origin,
        trusted_origin=options.cloud_origin,
        owner_sub=options.owner_sub,
        device_id=options.device_id,
        signing_key=signing_key,
        dispatcher_factory=approved_local_project,
    )


def main(argv: list[str] | None = None) -> int:
    options = _parser().parse_args(argv)
    try:
        asyncio.run(_connect(options))
    except (CloudHandshakeDeniedError, LocalApprovalDeniedError, ValueError, OSError):
        print("Local Cloud connection denied", file=sys.stderr)
        return 1
    print("One authorized project-presence request completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
