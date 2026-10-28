# Local KiCad Cloud connector — offline read-only boundary (candidate)

**Status: not connected and not deployed.** This is an isolated, import-only
policy module (`src/kicad_mcp/cloud_readonly_boundary.py`) plus an
offline-only Ed25519 proof module (`src/kicad_mcp/cloud_device_proofs.py`)
for a *future* local-device connector. It is not registered in the MCP server, GUI, plugin,
background service, pairing flow, Cloud WebSocket or the native KiCad engine.

## Where it fits

The Cloud repository's reviewed v1 transport envelope defines
`connector.read_request` with `requestId`, `deviceId`, `projectId`,
`operation`, and `deadlineUnixMs`. Its Cloud WebSocket route currently
authenticates device and session bootstrap only; **after `connector.ready`
the Cloud does not yet dispatch any read requests or native operations**.
Production `PAIRING_DEVICE_API_ENABLED` and `CONNECTOR_WS_ENABLED` both remain
**false**. This local PR changes neither setting.

A later *separately reviewed, authenticated* device transport will mint
`VerifiedLocalBinding` using the locally authenticated device identity and
a current owner/client/project authorization grant. **Never construct it
directly from JSON or owner/device claims supplied by Cloud messages**.
The owner separately configures `OperatorProject` on their workstation:
opaque project UUID, device UUID, absolute project directory and a filename
stem. The Cloud cannot choose or receive a local filesystem path.

`inspect_readonly()` accepts one **strict 1 KiB v1 frame**, authenticates
nothing itself, rechecks both identity IDs and the operation against the
trusted binding and operator policy, requires a valid opaque session UUID
and a trusted lease expiring within at most five minutes, rejects expired
leases and read deadlines beyond that lease or 30 seconds, and checks only the existence of exactly three direct files:
`*.kicad_pro`, `*.kicad_pcb` and `*.kicad_sch`. It follows no symlinks, uses
component-by-component `openat(O_NOFOLLOW | O_DIRECTORY)` for the folder,
and `stat(..., follow_symlinks=False)` relative to the opened descriptor.
It returns booleans, opaque UUIDs, and an **offline preview kind** — never
project names, file bytes, directory paths, or manufacturing outputs.
This first version requires POSIX directory-descriptor no-follow semantics:
**Windows is explicitly rejected**, rather than silently using weaker path
traversal. Windows support requires a separately reviewed Windows-native
handle/reparse-point implementation and security tests.

Only `project_summary` is accepted; `run_drc`, `run_erc`, all remote writes,
native execution and export are denied. If even one security precondition
fails, the entire request fails closed.

## Offline device cryptography (not enrollment or Cloud authentication)

The Cloud's existing outbound WebSocket protocol asks for two domain-separated
Ed25519 signatures during handshake:

- `device.challenge` → `device.proof`: sign exactly
  `kicad-cloud-device-handshake-v1\0{challengeId}\0{deviceId}\0{nonce}`.
- `connector.session_challenge` → `connector.session_proof`: sign exactly
  `kicad-cloud-bound-session-v1\0{sessionId}\0{challengeId}\0{deviceId}\0{nonce}\0{binding}`.

The offline proof helpers check canonical UUIDs, base64url 32-byte nonces and
connection binding, strict JSON field allowlists, device identity and a
challenge expiry bounded by 60 seconds. They take a **caller-held, in-memory**
`Ed25519PrivateKey` and emit only a Cloud v1 signature frame. The project
now explicitly depends on `cryptography` for these helpers. Tests verify
actual signatures using independent public-key verification and test that
tampering with device/session/connection identity invalidates a signature;
signing never writes or persists a private key.

**This is not Cloud server authentication:** an attacker-controlled service
could still submit a syntactically valid challenge. A future transport MUST
verify the Cloud TLS host/certificate and endpoint identity *before* signing,
maintain per-connection proof state to prevent cross-socket challenge reuse,
handle key storage/revocation in an approved keystore, and independently verify
owner OAuth authorization and active project/client grants. No transport,
device enrollment, key persistence, background service or production use is
implemented here.

## Local review / fixture tests

On a trusted development checkout, run:

```sh
PYTHONPATH=src python3 -m pytest -q tests/cloud/
```

The tests include cryptographic Ed25519 challenge proof roundtrips with
ephemeral keys, the checked-in KiCad 10 demo schematic and PCB, as well as
malformed, duplicate-field, cross-device, cross-project, symlink, directory
replacement, session lease/deadline, forbidden operation and content-leakage denials.

`tests/cloud/test_isolated_authorization_lifecycle.py` additionally uses a
**synthetic mutable grant/session state** to exercise current client/project
permission intersection, revocation between requests, disconnect, duplicate
sequence, wrong owner/client/device/session and a device lease that expires
before a queued read. This is an **offline fixture**, not a cryptographic
device authentication test, real OAuth verifier, live PostgreSQL-backed Cloud
read gate, Cloud-to-local dispatcher or actual owner project grant. Fixture
state deliberately models the Cloud side only; it cannot be used as a
production authority or session credential. Source and test code never
contact Cloud, start KiCad, mutate an owner's design, send keys over the
network or require a production account.

## Loopback-only TLS/WebSocket interoperability fixture

`tests/cloud/test_isolated_tls_websocket_handshake.py` exercises the
existing Cloud v1 **wire sequence**, not just signature construction:
`device.hello` → `device.challenge` → signed `device.proof`
→ `connector.session_challenge` → signed `connector.session_proof`
→ `connector.ready`. It starts a **localhost-only** fake Cloud server,
issues a temporary synthetic TLS certificate for `localhost`, verifies
that certificate and DNS hostname through Python's `ssl` trust checks,
and uses independent server-side Ed25519 verification of both proof bytes.
No real Cloud user or device identity is ever issued or enrolled.

Negative cases require TLS rejection before *any* device handshake for a
wrong certificate or hostname; challenge state/cross-device mismatches
also prevent proof release. The test-only client will not connect to a
non-loopback host, a plain `ws://` endpoint, a changed WS path, or a
credential-bearing/query URL. `websockets` is an explicit **development
dependency**, not a deployed local connector or background service.

The synthetic TLS private key lives only in the pytest temporary directory
and is unrelated to any production credential; tests clean it up. This
fixture does not provide actual production server trust configuration,
a deployed outbound transport, OAuth login, device enrollment, revocation
against a live PostgreSQL database, or Cloud-to-KiCad read dispatch.
**Do not treat a successful fake-server handshake as permission to
enable production pairing or WebSocket flags.**

## Session-bound, offline-only read dispatch and WebSocket fixture

The local-only `cloud_read_dispatch.py` provides a single-session
`LocalReadDispatch` for **already independently authorized** local reads.
It enforces one read at a time, strictly advancing sequence numbers,
a maximum of 32 reads per session, **unique request IDs**, the existing
approved device/project file-presence boundary and deadline re-validation
**after** inspection. It consumes sequences even on denied inspections
and permanently fences an in-flight result if `close()` races an inspection.

A `current_authorization` predicate is **mandatory**. The trusted future
transport must supply a fresh, independently verified owner/client/device/
project grant **and session state**; a missing, non-Boolean, failing or
revoked predicate returns a generic denial. The dispatcher checks it before
and after local file inspection. Test harnesses provide explicit synthetic
predicates: **a test predicate returning True is not a production grant**.
Tests cover revoked grants before and during a blocked read, repeated request
IDs with new sequence numbers, provider failures and disconnect races.

The future transport MUST call `close()` when a verified socket disconnects,
a grant is revoked or a session expires. The checks here are not an atomic
delivery authorization: the real server/transport must independently enforce
a current grant and connection binding immediately before sending any response,
to avoid revocation races after this method returns. It contains **no live
transport, OAuth verifier, server credential, owner enrollment, automatic
project map, native KiCad execution, file content reader or background
worker**.

`test_isolated_read_dispatch_websocket.py` connects this dispatcher
to a **synthetic fake Cloud over localhost-only WSS**, with ephemeral
Ed25519 device/session signatures and a temporary TLS certificate.
Its test-only read envelope supplies a fixture sequence; the locally
trusted test harness supplies the actual authorized sequence and an
operator-selected project mapping, **never a sequence/authorization
from the wire itself**. The allowed request returns only three file
presence booleans. A remote `run_drc` request is rejected and
the fake WebSocket closes. Read-after-disconnect is denied.

**These are NOT current Cloud protocol frames.** The real Cloud v1
WebSocket implementation still deliberately rejects all application
messages after `connector.ready`. Actual authorized Cloud-to-local
read dispatch requires a separate security-reviewed protocol extension,
signed server-side PostgreSQL grant verification and immutable socket
context, explicit project owner approval, a revocation notice and
controlled trust-root configuration. Do not enable production flags or
present this offline test as live KiCad connectivity.

## Gates before any live connection

1. Complete a separate owner-controlled enrollment and actual OAuth
   user consent/authorization, with revocable Ed25519 device credentials
   stored in an approved local keystore.
2. Review a transport that authenticates the remote Cloud endpoint and
   binds accepted requests to *verified* Cloud session, project grants
   and this local device. Upgrade/read dispatch is **not implemented** by
   this PR. Test full revocation, expiry, abort, and reconnect against an
   isolated Cloud/PostgreSQL instance first.
3. Require a human-selected, explicitly enabled project map; obtain an
   owner-approved test project before performing any real KiCad DRC/ERC.
   Avoid disclosing project paths or contents to Cloud.
4. Prove network/TLS and ingress-source trust, distributed rate limits
   and device proof on an accepted private test environment; do not
   bypass the current production device-ingress security block.
5. Keep production pairing, WebSocket and write/manufacturing flags OFF
   until every above check passes independently.
