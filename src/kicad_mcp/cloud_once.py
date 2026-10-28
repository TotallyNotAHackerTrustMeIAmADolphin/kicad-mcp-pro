"""Manual, one-shot Cloud project-presence connector; never auto-started.

The owner must explicitly choose a project and an already enrolled device key.
No pairing, OAuth authorization, device registration, filesystem discovery,
KiCad execution or background service is created by this command. The Cloud
server independently verifies its live OAuth client/project grant.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
)

from kicad_mcp.cloud_outbound_handshake import (
    HandshakeReceipt,
    execute_single_approved_read,
)
from kicad_mcp.cloud_read_dispatch import LocalReadDispatch
from kicad_mcp.cloud_readonly_boundary import (
    OperatorProject,
    VerifiedLocalBinding,
    _open_operator_directory,
)


class LocalApprovalDeniedError(ValueError):
    """Fail closed, without returning private-key or filesystem details."""


_LOCAL_APPROVAL_DENIED = "local approval denied"

_OWNER_KEY_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_BINDING_SUFFIX = ".cloud-binding-v1.json"


def _open_owner_private_dir(filename: Path) -> int:
    """Pin an owner-private parent through a no-follow directory-component walk."""
    getuid = getattr(os, "getuid", None)
    if (
        os.name != "posix"
        or not callable(getuid)
        or not isinstance(filename, Path)
        or not filename.is_absolute()
        or _OWNER_KEY_FILENAME.fullmatch(filename.name) is None
        or any(part in {".", ".."} for part in filename.parts[1:])
    ):
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    directory_fd: int | None = None
    try:
        directory_fd = _open_operator_directory(filename.parent)
        metadata = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != getuid()
            or metadata.st_mode & 0o077
        ):
            raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
        return directory_fd
    except (OSError, ValueError) as exc:
        if directory_fd is not None:
            os.close(directory_fd)
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED) from exc


def _load_owner_key(filename: Path) -> Ed25519PrivateKey:
    """Read owner-only PEM by a pinned private directory FD and no-follow basename."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    getuid = getattr(os, "getuid", None)
    if (
        os.name != "posix"
        or type(nofollow) is not int
        or type(nonblock) is not int
        or not callable(getuid)
    ):
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    directory_fd = _open_owner_private_dir(filename)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            filename.name,
            # A substituted FIFO must not block before fstat rejects it.
            os.O_RDONLY | nofollow | nonblock | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or not 1 <= metadata.st_size <= 8192
        ):
            raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
        key = load_pem_private_key(os.read(descriptor, 8193), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
        return key
    except (OSError, ValueError, TypeError) as exc:
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _read_owner_binding(filename: Path) -> dict[str, str]:
    """Read owner-only pairing metadata by a pinned no-follow directory FD."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    getuid = getattr(os, "getuid", None)
    if type(nofollow) is not int or type(nonblock) is not int or not callable(getuid):
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    directory_fd = _open_owner_private_dir(filename)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            filename.name + _BINDING_SUFFIX,
            # A substituted FIFO must not block before fstat rejects it.
            os.O_RDONLY | nofollow | nonblock | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or not 1 <= metadata.st_size <= 512
        ):
            raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
        raw = os.read(descriptor, 513)

        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            if len({k for k, _ in pairs}) != len(pairs):
                raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
            return dict(pairs)

        value = json.loads(raw, object_pairs_hook=unique)
        if (
            not isinstance(value, dict)
            or set(value) != {"origin", "deviceId", "fingerprint"}
            or not all(isinstance(v, str) for v in value.values())
            or len(value["origin"]) > 256
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                value["deviceId"],
            )
            is None
            or re.fullmatch(r"[0-9a-f]{64}", value["fingerprint"]) is None
        ):
            raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
        return value
    except (OSError, ValueError, TypeError) as exc:
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _save_owner_binding(filename: Path, *, origin: str, device_id: str, fingerprint: str) -> None:
    """Pin approved enrollment to one HTTPS origin and device, never overwrite."""
    # The fields are independently validated by the Cloud enrollment response.
    expected = {"origin": origin, "deviceId": device_id, "fingerprint": fingerprint}
    if (
        not isinstance(origin, str)
        or not origin.startswith("https://")
        or len(origin) > 256
        or re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", device_id
        )
        is None
        or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
    ):
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if type(nofollow) is not int:
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    directory_fd = _open_owner_private_dir(filename)
    descriptor: int | None = None
    try:
        # Existing metadata, even with identical contents, cannot represent a
        # new pairing. O_EXCL fails closed instead of reopening by pathname.
        descriptor = os.open(
            filename.name + _BINDING_SUFFIX,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        body = json.dumps(expected, separators=(",", ":"), sort_keys=True).encode()
        with os.fdopen(descriptor, "wb", buffering=0) as output:
            descriptor = None
            try:
                if output.write(body) != len(body):
                    raise OSError(_LOCAL_APPROVAL_DENIED)
                os.fsync(output.fileno())
            except BaseException:
                # Invalidate *our open inode*, not a possibly replaced path.
                # An incomplete record is never published as trusted pairing.
                os.ftruncate(output.fileno(), 0)
                raise
    except (OSError, ValueError, TypeError) as exc:
        # Never unlink by name after a failed write: another same-user
        # process could have moved our inode and replaced the path.
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def _load_bound_owner_key(filename: Path, origin: str, device_id: str) -> Ed25519PrivateKey:
    """Reject a different Cloud or device before using an enrolled owner key."""
    record = _read_owner_binding(filename)
    if record["origin"] != origin or record["deviceId"] != device_id:
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    key = _load_owner_key(filename)
    der = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    if hashlib.sha256(der).hexdigest() != record["fingerprint"]:
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    return key


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="One approved KiCad Cloud metadata read")
    parser.add_argument("--cloud-origin", required=True, help="Trusted HTTPS origin chosen locally")
    parser.add_argument("--owner-sub", required=True, help="Enrolled account subject")
    parser.add_argument("--device-id", required=True, help="Already enrolled device UUID")
    parser.add_argument("--project-id", required=True, help="Explicitly allowed project UUID")
    # No LLM/CLI-supplied filesystem paths. The already-registered device
    # and project UUIDs select fixed local owner-private records instead.
    parser.add_argument(
        "--allow-once",
        action="store_true",
        required=True,
        help="Explicit local consent; one presence-only read, no native operation",
    )
    return parser


def _confirm_local_read(options: argparse.Namespace) -> tuple[int, int]:
    """Require a deliberate foreground terminal acknowledgement before key use.

    This blocks unattended shell redirection, not a malicious process with its
    own PTY or the same OS account. Real user identity still needs trusted UI.
    """
    if (
        not sys.stdin.isatty()
        or not sys.stdout.isatty()
        or not isinstance(options.project_directory, Path)
        or not options.project_directory.is_absolute()
    ):
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    challenge = secrets.token_hex(4).upper()
    print("One-time metadata-only KiCad Cloud read (no project contents).")
    print(f"Cloud origin: {options.cloud_origin!r}")
    print(f"Owner account: {options.owner_sub!r}")
    print(f"Device UUID: {options.device_id!r}")
    print(f"Project UUID: {options.project_id!r}")
    print(f"Local directory: {str(options.project_directory)!r}")
    print(f"Local project stem: {options.filename_stem!r}")
    print(f"Owner key file: {str(options.private_key_file)!r}")
    answer = input(f"Type APPROVE {challenge} to authorize exactly one read: ")
    if answer != f"APPROVE {challenge}":
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    # Start both deadlines at the actual foreground approval, never after
    # a potentially slow remote device/session handshake.
    return time.time_ns() // 1_000_000 + 30_000, time.monotonic_ns() + 30_000_000_000


async def _connect(
    options: argparse.Namespace, authorization_window: tuple[int, int]
) -> HandshakeReceipt:
    wall_cutoff_ms, monotonic_cutoff_ns = authorization_window
    if (
        not options.allow_once
        or not options.project_directory.is_absolute()
        or time.monotonic_ns() >= monotonic_cutoff_ns
    ):
        raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
    signing_key = _load_bound_owner_key(
        options.private_key_file, options.cloud_origin, options.device_id
    )

    def approved_local_project(receipt: HandshakeReceipt) -> LocalReadDispatch:
        # This is an independent, local, time-limited operator grant, never a
        # Cloud-supplied authorization flag or a synthetic always-true grant.
        # Even a valid device handshake must not renew expired local consent.
        if time.monotonic_ns() >= monotonic_cutoff_ns:
            raise LocalApprovalDeniedError(_LOCAL_APPROVAL_DENIED)
        return LocalReadDispatch(
            verified=VerifiedLocalBinding(
                device_id=receipt.device_id,
                project_id=options.project_id,
                operations=frozenset({"project_summary"}),
                session_id=receipt.session_id,
                session_expires_unix_ms=wall_cutoff_ms,
            ),
            operator_project=OperatorProject(
                device_id=options.device_id,
                project_id=options.project_id,
                directory=options.project_directory,
                filename_stem=options.filename_stem,
            ),
            current_authorization=lambda: time.monotonic_ns() < monotonic_cutoff_ns,
            max_reads=1,
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
        from kicad_mcp.cloud_local_registry import resolve_registered_read

        selected = resolve_registered_read(
            owner_sub=options.owner_sub,
            origin=options.cloud_origin,
            device_id=options.device_id,
            project_id=options.project_id,
        )
        options.project_directory = selected.project_directory
        options.filename_stem = selected.filename_stem
        options.private_key_file = selected.key_file
        approval_window = _confirm_local_read(options)
        asyncio.run(_connect(options, approval_window))
    except (ValueError, OSError, EOFError, KeyboardInterrupt):
        print("Local Cloud connection denied", file=sys.stderr)
        return 1
    print("One authorized project-presence request completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
