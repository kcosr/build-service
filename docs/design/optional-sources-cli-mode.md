# build-service: Optional Sources & CLI-Driven Mode — Design Spec

## Overview

Extend `build-service` so that **sources and artifacts are optional** and all client settings can be provided via **CLI flags and environment variables**, removing the requirement for a `.build-service/config.toml` directory. This enables a lightweight "exec" use case where remote agents run commands on the local machine through an SSH tunnel with no file exchange needed.

No new server endpoint. The existing `/v1/builds` endpoint is reused with minimal changes: the source archive becomes optional, and a new **default workspace** concept handles the case where no workspace ID is specified.

## Design Principles

- **No config directory required** — everything expressible via CLI flags and env vars
- **Three-tier config layering** — config file (lowest) → env vars → CLI flags (highest)
- **Backwards compatible** — existing configs and workflows unchanged
- **Consistent workspace model** — every request uses a workspace; behavior is the same whether sources are provided or not
- **Fail loud** — if workspace can't be resolved (no ID, no default configured), the request is rejected

---

## Workspace Model

### How It Works Today

Every build runs in a workspace — a directory under `build.workspace_root`:

- **Ephemeral workspace**: auto-generated ID, created per request, cleaned up after
- **Reusable workspace**: client-specified ID, persistent, TTL + GC managed

Sources are always extracted into the workspace. `cwd` is always relative to the workspace root.

### What Changes

1. **Sources become optional** — if no source archive is provided, the workspace still exists, sources just aren't extracted into it
2. **Default workspace** — a new server config field provides a permanent workspace path for requests that don't specify a workspace ID
3. **Resolution order**:
   - Client specifies workspace ID → use managed workspace (existing behavior)
   - Client omits workspace ID → use `default_workspace_path` from server config
   - No workspace ID and no default configured → reject request with error

The default workspace is **permanent** — no TTL, no GC, never cleaned up. It's just a directory that always exists. Sources can be extracted into it, commands run in it, `cwd` is relative to it. It can be any path on the filesystem, not restricted to `workspace_root`.

### Default Workspace Validation

The server **validates `default_workspace_path` at startup**. If the field is set but the directory does not exist, the server refuses to start with a clear error. The server does not auto-create the directory — the admin must create it beforehand.

### `cwd` Behavior (Unchanged)

`cwd` is always **relative** to the workspace, regardless of whether sources are present. This is the same as today — no special casing, no absolute paths.

---

## Client Changes: `build-cli`

### Config Resolution (New Layering)

**Priority** (highest wins):

1. **CLI flags** — `--endpoint`, `--source`, `--artifact`, `--cwd`, `--timeout`, `--env`, `--token`
2. **Environment variables** — `BUILD_SERVICE_ENDPOINT`, `BUILD_SERVICE_SOURCES`, etc.
3. **Config file** — `.build-service/config.toml` (searched up from cwd, as today)

If no config file is found, CLI flags and env vars must provide enough to make the request. At minimum, an endpoint is required. Sources, artifacts, cwd, and env are all optional.

### New/Extended CLI Flags

| Flag | Env Var | Description | Config File Equivalent |
|------|---------|-------------|----------------------|
| `--endpoint <URL>` | `BUILD_SERVICE_ENDPOINT` | Server endpoint (`unix://` or `http://`) | `connection.endpoint` |
| `--token <TOKEN>` | `BUILD_SERVICE_TOKEN` | Bearer token for HTTP auth | `connection.token` |
| `--source <GLOB>` | `BUILD_SERVICE_SOURCES` | Source include pattern (repeatable). Env var: comma-separated. | `sources.include` |
| `--source-exclude <GLOB>` | `BUILD_SERVICE_SOURCES_EXCLUDE` | Source exclude pattern (repeatable). Env var: comma-separated. | `sources.exclude` |
| `--artifact <GLOB>` | `BUILD_SERVICE_ARTIFACTS` | Artifact include pattern (repeatable). Env var: comma-separated. | `artifacts.include` |
| `--artifact-exclude <GLOB>` | `BUILD_SERVICE_ARTIFACTS_EXCLUDE` | Artifact exclude pattern (repeatable). Env var: comma-separated. | `artifacts.exclude` |
| `--cwd <PATH>` | `BUILD_SERVICE_CWD` | Working directory (relative to workspace) | *(new)* |
| `--timeout <SECS>` | `BUILD_SERVICE_TIMEOUT` | Command timeout | `request.timeout_sec` |
| `--env <KEY=VAL>` | *(use actual env vars)* | Environment variable to forward (repeatable) | `request.env` |
| `--workspace-reuse` | `BUILD_SERVICE_WORKSPACE_REUSE` | Reuse workspace *(existing)* | `workspace.reuse` |
| `--workspace-id <ID>` | `BUILD_SERVICE_WORKSPACE_ID` | Workspace identifier *(existing)* | `workspace.id` |

### Behavior Changes

1. **Config file is optional** — if not found, proceed with CLI flags and env vars only (instead of erroring)
2. **Sources are optional** — if no `--source` flags, no env var, and no config file sources: skip zip creation, send request without source multipart part
3. **Artifacts are optional** — if no `--artifact` flags, no env var, and no config file artifacts: skip artifact download
4. **`--cwd` support** — relative path sent in request metadata; server resolves it relative to the workspace (same as existing `cwd` behavior)

### CLI Usage Examples

```bash
# ── No config file needed ──────────────────────────────

# Simple command execution (no sources, no artifacts)
# Server uses default workspace
build-cli --endpoint unix:///tmp/build-service.sock \
  make -j4 all

# With relative cwd within the default workspace
build-cli --endpoint unix:///tmp/build-service.sock \
  --cwd my-project \
  cargo build --release

# With explicit workspace ID
build-cli --endpoint unix:///tmp/build-service.sock \
  --workspace-id my-project --workspace-reuse \
  make -j4 all

# With sources uploaded, artifacts downloaded
build-cli --endpoint unix:///tmp/build-service.sock \
  --source 'src/**' --source 'Makefile' \
  --source-exclude 'src/test/**' \
  --artifact 'dist/**' \
  npm run build

# With env vars and timeout
build-cli --endpoint unix:///tmp/build-service.sock \
  --env CC=clang --env VERBOSE=1 \
  --timeout 600 \
  make

# ── With config file present (CLI overrides config) ───

# Config provides defaults; CLI overrides timeout
build-cli --timeout 900 make -j4 all

# Config provides sources; CLI adds an extra artifact pattern
build-cli --artifact 'coverage/**' make test

# ── Via environment variables ─────────────────────────

export BUILD_SERVICE_ENDPOINT="unix:///tmp/build-service.sock"

# build-cli and the wrapper both work with minimal flags
build-cli make -j4 all
build-cli --cwd my-project cargo test
```

### Wrapper Script Changes

Update `build-wrapper.sh` to work without a config directory:

```
if .build-service/config.toml found:
    → existing behavior (exec build-cli <tool> <args>)
elif BUILD_SERVICE_ENDPOINT env var is set:
    → exec build-cli <tool> <args>
    (build-cli picks up endpoint and other settings from env vars)
else:
    → fall back to real tool
```

This makes the wrapper transparent when `BUILD_SERVICE_ENDPOINT` is set — agents run `make` and it goes through the tunnel automatically.

---

## Server Changes

### 1. Make Source Archive Optional

**`src/http.rs`** — In the `/v1/builds` multipart handler:

```
Current:  source_path = None → bad_request("missing source field")
Proposed: source_path = None → proceed with source = None
```

### 2. Default Workspace

**New config field:**

```toml
[build]
# ... existing fields ...
default_workspace_path = "/home/user/workspace"   # NEW: optional, any path
```

- Can be **any path** on the filesystem (not restricted to `workspace_root`)
- **Validated at startup** — server refuses to start if the path is set but does not exist
- **Permanent** — no TTL, no GC, never cleaned up by the workspace manager

**Workspace resolution in `src/build.rs`:**

```
if client specifies workspace ID:
    → use managed workspace (existing behavior, unchanged)
elif config.build.default_workspace_path is set:
    → use that path as the workspace
    → skip workspace creation (already validated at startup)
    → skip workspace GC/TTL (permanent)
else:
    → reject request: "workspace ID required (no default workspace configured)"
```

### 3. Skip Source Extraction When No Sources

**`src/build.rs`** — In `prepare_workspace`:

```
if source_archive is Some(path):
    → extract into workspace (existing behavior)
elif source_archive is None:
    → skip extraction, workspace is used as-is
```

The rest of the build pipeline is unchanged: `cwd` resolves relative to the workspace, command runs there, artifacts collect relative to there.

### 4. Artifact Download Size Limit

**New config field:**

```toml
[artifacts]
storage_root = "/var/lib/build-service/artifacts"
max_artifact_bytes = 536870912    # NEW: optional, max size of artifact zip per request (512 MB)
# ... existing fields ...
```

**Server-side enforcement** — during artifact collection, if the zip exceeds `max_artifact_bytes`, the build fails with an error. This is enforced in `src/artifacts.rs` when packaging the zip, before it's written to storage.

This complements the existing upload limits (`max_upload_bytes`, `max_extracted_bytes`) with a download-side cap:

| Limit | Direction | Scope | Config Field |
|-------|-----------|-------|-------------|
| `max_upload_bytes` | Upload | Source archive size | `[build]` |
| `max_extracted_bytes` | Upload | Extracted source size | `[build]` |
| `max_artifact_bytes` | Download | Artifact zip size per request | `[artifacts]` — **NEW** |
| `max_bytes` | Storage | Total artifact storage on disk | `[artifacts]` |

### 5. Server Config Summary

```toml
schema_version = "3"

[build]
workspace_root = "/var/lib/build-service/workspaces"
default_workspace_path = "/home/user/workspace"     # NEW (optional)
# ... rest unchanged ...

[artifacts]
storage_root = "/var/lib/build-service/artifacts"
max_artifact_bytes = 536870912                       # NEW (optional)
# ... rest unchanged ...
```

Two new fields total. Everything else stays the same.

---

## Protocol Changes

### Multipart Request

Source part becomes **optional**:

```
POST /v1/builds
Content-Type: multipart/form-data

[metadata] — required (JSON)
[source]   — optional (zip archive)
```

### Request Metadata

No schema changes. The existing `cwd` and `workspace` fields work as-is:

```jsonc
{
  "schema_version": "3",
  "command": "make",
  "args": ["-j4", "all"],
  "cwd": "subdir",                  // optional, relative to workspace
  "timeout_sec": 300,
  "env": { "CC": "clang" },
  "artifacts": { "include": ["dist/**"], "exclude": [] },
  "workspace": { "reuse": true, "id": "my-project" }  // optional
}
```

When `workspace` is omitted or null, the server uses the default workspace path. When `source` multipart part is omitted, no extraction happens.

### Response

Unchanged. NDJSON streaming with `build`, `stdout`, `stderr`, `exit` event types.

When no artifacts are requested, the `exit` event omits the `artifacts` field (already the case when no artifacts are collected).

---

## Security

No changes to the security model:

- **Command allowlist** — `[build.commands]` applies to all requests
- **Environment allowlist** — `[build.environment.allow]` applies to all requests
- **Timeout enforcement** — `[build.timeouts]` applies to all requests
- **Auth** — bearer token for HTTP; UDS file permissions
- **No shell interpretation** — commands exec'd directly
- **`cwd` validation** — relative path, resolved within workspace (existing behavior)
- **Artifact size limit** — `max_artifact_bytes` prevents oversized downloads (new)

The command allowlist is the real security boundary. Once a command is allowed, it can access any path the process user can, regardless of workspace or cwd.

---

## SSH Tunnel Setup

Same as current build-service:

```bash
# UDS tunnel (preferred)
ssh -R /tmp/build-service.sock:/run/build-service.sock remote-host

# TCP tunnel
ssh -R 9100:localhost:9100 remote-host
```

On the remote machine:
```bash
export BUILD_SERVICE_ENDPOINT="unix:///tmp/build-service.sock"
# Now build-cli and build-wrapper both work
```

---

## Implementation Plan

### Phase 1: Server — Default Workspace + Optional Sources
1. Add `default_workspace_path` to server config (`[build]` section)
2. Validate at startup: if set, directory must exist; fail to start otherwise
3. Implement workspace resolution: client ID → default path → error
4. Make source multipart part optional in `src/http.rs`
5. Skip source extraction in `prepare_workspace` when source is `None`
6. Tests: sourceless request with default workspace, sourceless request without default (expect error), sources with default workspace (extraction works), startup validation failure

### Phase 2: Server — Artifact Download Limit
7. Add `max_artifact_bytes` to `[artifacts]` config
8. Enforce during artifact zip creation in `src/artifacts.rs`
9. Tests: artifact exceeding limit returns error

### Phase 3: Client — CLI Flags & Optional Config
10. Add new CLI flags to `build-cli` (clap): `--source`, `--source-exclude`, `--artifact`, `--artifact-exclude`, `--cwd`, `--env`
11. Implement three-tier config resolution (file → env → flags)
12. Make config file optional — don't error when not found if CLI flags/env vars provide enough
13. Skip zip creation when no sources to send
14. Tests: CLI-only invocation, config + CLI merge, env var layering

### Phase 4: Wrapper Updates
15. Update `build-wrapper.sh` to detect `BUILD_SERVICE_ENDPOINT` env var
16. Work without config directory present
17. Test wrapper in both modes

### Phase 5: Future Enhancements
- Argument validation patterns per command (regex per arg position or subcommand allowlist)
- `build-cli init` — generate config file from CLI flags
- Named default workspaces (multiple defaults keyed by name)

---

## Decisions Log

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| 1 | Artifact collection with default workspace | Artifacts relative to workspace, same as today | Consistent behavior; no special casing |
| 2 | Naming | Keep `build-cli` / `build-service` | Builds are still the primary use case; exec is an extension |
| 3 | Default workspace creation | Server fails to start if path doesn't exist | Fail loud; admin must create the directory. No surprises at request time |
| 4 | Default workspace location | Any path, not restricted to `workspace_root` | It's a fixed configured path, not managed by workspace GC |
| 5 | Artifact download limit | Server-side `max_artifact_bytes` in `[artifacts]` config | Server packages the zip; server enforces the limit. Complements upload-side limits |
