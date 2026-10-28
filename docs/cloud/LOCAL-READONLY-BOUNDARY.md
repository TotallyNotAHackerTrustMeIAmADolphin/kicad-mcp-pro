# Local KiCad Cloud connector — offline read-only boundary (candidate)

**Status: not connected and not deployed.** This is an isolated, import-only
policy module (`src/kicad_mcp/cloud_readonly_boundary.py`) for a *future*
local-device connector. It is not registered in the MCP server, GUI, plugin,
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
trusted binding and operator policy, rejects stale/future deadlines beyond
30 seconds, and checks only the existence of exactly three direct files:
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

## Local review / fixture tests

On a trusted development checkout, run:

```sh
PYTHONPATH=src python3 -m pytest -q tests/cloud/test_local_readonly_boundary.py
```

The tests include the checked-in KiCad 10 demo schematic and PCB, as well as
malformed, duplicate-field, cross-device, cross-project, symlink, directory
replacement, deadline, forbidden operation and content-leakage denials.
They do not contact Cloud, start KiCad, mutate an owner's design, send keys
over the network or require a production account.

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
