# KiCad Cloud — owner-controlled local project summary (pre-production)

**Status: implementation in two DRAFT pull requests, not deployed.** The local
client is [KiCad MCP Pro PR #1513](https://github.com/oaslananka/kicad-mcp-pro/pull/1513)
and the compatible Cloud pairing, browser authorization and read relay is
[KiCad Cloud PR #64](https://github.com/oaslananka/kicad-mcp-pro-cloud/pull/64).
Neither PR is a live production connection. The existing Cloud deployment
reports `remoteConnector=not_implemented`; `PAIRING_DEVICE_API_ENABLED` and
`CONNECTOR_WS_ENABLED` remain OFF. Do not merge or enable these features
without an independent security and owner acceptance.

## What works in an approved isolated environment

The local operator can explicitly invoke two commands:

- `python -m kicad_mcp.cloud_pair --begin-pairing` creates or safely reuses an
  owner-only Ed25519 key. It initiates a device challenge over verified HTTPS,
  displays the short user code and challenge UUID, and **waits for an actual
  signed-in owner to approve it in the Cloud browser**. Only after this
  confirmation does it sign the one-use device proof and redeem the challenge.
  The resulting device is **enrolled but disabled**. No private-key bytes are
  uploaded. The local key directory must exist, be owned by the same POSIX
  user, have no symlink substitution and forbid group/other access.
- `python -m kicad_mcp.cloud_once --allow-once` opens an authenticated
  HTTPS/WSS session with an already enrolled and explicitly enabled device
  and independently chosen local KiCad project. It permits **one** owner-approved
  `project_summary` presence-only read, with a 30-second local lease; it
  closes the session on completion or denial. It does not start automatically
  or require the existing local KiCad MCP service to be restarted.

The Cloud's actual OAuth JWT verifier and PostgreSQL gates require a
`projects:read` client consent, an enabled unrevoked owner device, an enabled
owner project and a separate per-client `readonly` project grant. The
Cloud browser `/devices` page exposes device activation, metadata-only
project registration (opaque UUID, alias, no local path), owner subject and
the **explicit project-to-OAuth-client grant/revoke form**. The existing
`/connections` page lists clients with OAuth consent and supports revoke.
Browser mutations use same-origin, owner/session/action-specific signed CSRF;
a revoked key cannot be reactivated and a revoked client needs **fresh**
consent after its cutoff to receive another grant.

## Reproducible manual workflow (isolated test deployment only)

The Cloud instance must be independently provisioned with **only the reviewed
database migrations, built-in OAuth identity, valid HTTPS/WSS ingress and
trusted device source**. Do not use production credentials, flags or shared
proxy settings to make a test pass. The instructions below are for a
separately approved, isolated Cloud test environment with these features
already enabled; they will fail closed against current production.

On a POSIX workstation with this checkout and `uv`:

```sh
# Private key stays on this workstation. Do not commit, upload or echo it.
umask 077
KEY_DIR="$HOME/.local/share/kicad-mcp-cloud"
install -d -m 0700 "$KEY_DIR"

# Set the independently verified HTTPS origin of the ISOLATED Cloud.
CLOUD_ORIGIN="https://cloud-test.example.invalid"

uv run --all-extras python -m kicad_mcp.cloud_pair \
  --cloud-origin "$CLOUD_ORIGIN" \
  --alias "My test workstation" \
  --private-key-file "$KEY_DIR/device-ed25519.pem" \
  --begin-pairing
```

In a browser **signed in as the intended owner of that isolated Cloud**,
open the exact `/devices/pairing` URL printed by the client and approve
its challenge UUID with the displayed short code. Return to the terminal
and press Enter before the challenge expires. Save the printed `deviceId`
as an opaque non-secret ID; keep the private-key file private. Do not
interpret enrollment as device activation.

In the Cloud browser `/devices`, explicitly enable the newly enrolled
device and register one read-only test project. Note its `projectId` and
your displayed `ownerSub`. Separately consent to an authorized AI client
with `projects:read` and explicitly grant *that client* `readonly` access
to *that project*. No Cloud action selects a local directory.

When a properly OAuth-authenticated client is ready to request this exact
project, start a single local one-shot session with the **local project
folder/stem chosen by the owner**:

```sh
uv run --all-extras python -m kicad_mcp.cloud_once \
  --cloud-origin "$CLOUD_ORIGIN" \
  --owner-sub "<ownerSub from Cloud /devices>" \
  --device-id "<deviceId from successful pairing>" \
  --project-id "<projectId registered in Cloud>" \
  --project-directory "/absolute/path/to/owner-selected/test-project" \
  --filename-stem "test-project" \
  --private-key-file "$KEY_DIR/device-ed25519.pem" \
  --allow-once
```

The separately authorized AI client must call
`POST /api/v1/connector/project-summary` with its valid OAuth Bearer token,
`Content-Type: application/json`, and **only** `deviceId` and `projectId`
as JSON fields while the one-shot session is active. The token must not
be pasted in logs, shell history, PR comments or documentation. The Cloud
server performs a fresh grant/session check before forwarding and a second
grant/token check before delivering a response. Successful output contains
only `projectPresent`, `boardPresent` and `schematicPresent` booleans;
a local filename, project content and private key never become response
fields. Failure is a generic denial; no remote fallback tool is offered.

## Security boundary and evidence

- All local file checks are on the **owner-selected direct child** of an
  absolute folder, using POSIX descriptor-relative no-follow metadata
  access. Symlinks and unsupported Windows-native handle semantics **fail
  closed**; Windows support requires its own independently reviewed
  handle/reparse-point implementation.
- Ed25519 device/session signatures use domain-separated Cloud v1 bytes.
  The local client checks hostname and CA before signing; compressed
  WebSocket frames and alternate origins/paths are rejected. Pairing
  requests use verified HTTPS, bounded response size, **no redirects or
  automatic retries**. Owner keys use exclusive creation and mode 0600.
- Only `project_summary` is accepted. Native KiCad execution, DRC/ERC,
  PCB mutation, manufacturing/export, local path discovery and arbitrary
  file reads are all denied. There is no background worker, persistent
  online connection or unattended reconnect.
- Real Cloud TypeScript handlers, PostgreSQL 17 migrations, JWT cryptographic
  verifier and Python TLS/Ed25519 one-shot reader have passed a **combined
  isolated cross-language acceptance** using synthetic owner/client/project
  identities and an isolated KiCad file-presence fixture. Cloud owner
  activation/grant/revocation tests have separately passed against a
  disposable PostgreSQL 17 database. These tests do **not** establish
  production owner OAuth login, approval of real project files or live
  end-to-end device provisioning.
- `tests/cloud/test_enrollment_one_shot_integration.py` additionally
  bridges the **actual local** enrollment implementation to the one-shot
  CLI with the **same generated Ed25519 key and persisted origin/device
  binding**. It verifies a synthetic owner challenge/redeem signature,
  strict private metadata, one direct-child project-presence summary,
  and rejection of a second read. The browser approval and network
  transport are **synthetic fixtures**; this is **not** a production Cloud,
  real browser OAuth, or real-owner acceptance test.
- `tests/cloud/test_enrollment_real_wss_integration.py` exercises the
  **actual persisted browser-paired Ed25519 identity** through verified
  localhost HTTPS-origin to a **real temporary CA-signed TLS WebSocket**
  peer, checking both device/session challenge signatures and a single
  `connector.read_result`/ACK with only three presence booleans. It uses
  synthetic pairing HTTP responses and synthetic browser approval, plus a
  disposable local KiCad file-presence fixture. Unlike the previous
  local-only transport stub, the actual outbound WSS client and read
  dispatcher execute; unlike a real owner acceptance, it exercises **no
  signed-in OAuth user, production Cloud server, or production data**.
- The local `tests/cloud/` suite is included in the full Python CI runner.
  For proportionate local validation, run
  `uv run --all-extras pytest -q tests/cloud/` and check the latest exact
  PR-head CI, coverage, security and supported-platform gates. Do not
  dismiss alerts to bypass a failing gate.

**Release blockers:** verified real-owner login/consent and device enrollment
in a privately approved isolated environment, review of trusted TLS ingress
and device-source rules, revocation during an actual local read, both PRs'
exact-head CI/security acceptance, and separate explicit production approval.
Until then, both PRs remain DRAFT and production flags remain OFF.
