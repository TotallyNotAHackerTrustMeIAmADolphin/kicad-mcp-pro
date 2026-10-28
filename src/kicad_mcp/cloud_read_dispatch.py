"""Fail-closed local-only sequenced read dispatcher. No network transport.

Only a separately reviewed and authenticated transport can supply the trusted
device/session binding and operator-approved local project mapping.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from kicad_mcp.cloud_readonly_boundary import (
    LocalReadDeniedError,
    OperatorProject,
    VerifiedLocalBinding,
    _validate_frame,
    inspect_readonly,
)

MAX_READS_PER_SESSION = 32


class LocalReadDispatch:
    """One session; serialized reads, expiry, disconnect and replay fencing.

    This object does NOT authenticate TLS, OAuth, keys, grants or a Cloud socket.
    No production transport calls it yet. A future transport must independently
    establish trust and close this dispatcher on disconnect and revocation.
    """

    def __init__(
        self,
        *,
        verified: VerifiedLocalBinding,
        operator_project: OperatorProject,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        self._verified = verified
        self._project = operator_project
        self._clock_ms = clock_ms if clock_ms is not None else lambda: time.time_ns() // 1_000_000
        self._lock = threading.Lock()
        self._closed = False
        self._busy = False
        self._last_sequence = 0

    def close(self) -> None:
        """Invalidate this session, including any pending read response."""
        with self._lock:
            self._closed = True

    def read(self, frame: bytes, *, sequence: int) -> dict[str, object]:
        """Inspect only approved local project file presence; deny all other work."""
        with self._lock:
            if (
                self._closed
                or self._busy
                or type(sequence) is not int
                or sequence != self._last_sequence + 1
                or sequence > MAX_READS_PER_SESSION
            ):
                raise LocalReadDeniedError("request denied")
            self._busy = True
            # Consumed before inspection, including any failed authorization.
            self._last_sequence = sequence

        try:
            response = inspect_readonly(
                frame,
                verified=self._verified,
                operator_project=self._project,
                now_unix_ms=self._clock_ms(),
            )
            # Recheck signed request expiry before return, including if local
            # file metadata inspection was blocked or time advanced.
            body = _validate_frame(frame, self._verified, self._project, self._clock_ms())
            if body["requestId"] != response["requestId"]:
                raise LocalReadDeniedError("request denied")
            with self._lock:
                if self._closed:
                    raise LocalReadDeniedError("request denied")
                return response
        finally:
            with self._lock:
                self._busy = False
