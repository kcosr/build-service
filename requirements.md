# Build Service

A host-side build service that executes `make` on the host when triggered from containers, while preserving the caller’s identity via Unix socket peer credentials.

## Reference Implementation

For Rust conventions (config, logging, error handling), reference:

```bash
git clone https://github.com/kcosr/acl-proxy.git
```

Key patterns to follow from acl-proxy:

- **Config** (`src/config/mod.rs`):
  - TOML with `serde::Deserialize` structs
  - `schema_version` field for forward compatibility
  - Default values via `#[serde(default = "default_fn")]` and standalone `fn default_*()` functions
  - Separate `validate()` method called after parsing
  - `ConfigError` enum with `thiserror` for typed errors

- **Logging** (`src/logging/mod.rs`):
  - `tracing` + `tracing-subscriber` for structured logging
  - `RotatingFileWriter` for size-based log rotation
  - Optional console + file output via `TeeWriter`
  - Non-blocking writes via channel + worker thread
  - Plain text format (not JSON)

- **Error handling**:
  - Custom error enums with `#[derive(Debug, thiserror::Error)]`
  - `#[error("message with {field}")]` for Display impl
  - `#[source]` attribute for error chaining

- **Cargo.toml**:
  - Align dependency versions and feature flags (tokio, serde, tracing, thiserror, clap, etc.)

## Purpose

- Run SIP stack builds on the host (dependent libraries remain on host)
- Allow AI coding agents to trigger builds from within containers
- Maintain user identity via Unix socket peer credentials (`SO_PEERCRED`)

## Environment

- Host OS: Rocky Linux
- Container runtime: Podman (rootless)
- Workspace bind mount: `/home/<user>/workspace` (identical path on host and container)
- Socket access group: configurable (e.g., `users`), must include all developers/agents that need to build

## Architecture

```
┌─────────────────────┐         ┌──────────────────────┐
│  Container          │         │  Host                │
│                     │         │                      │
│  make (wrapper)     │─────────│  build-service       │
│       │             │  Unix   │       │              │
│       ▼             │  Socket │       ▼              │
│  build-cli ─────────┼────────►│  Validate request    │
│                     │         │       │              │
│  Streams stdout/err │◄────────┼───────┤              │
│                     │         │       ▼              │
└─────────────────────┘         │  Drop privs (peer)   │
                                │       │              │
                                │       ▼              │
                                │  exec /usr/bin/make  │
                                │                      │
                                └──────────────────────┘
```

## Components

### 1. build-service (Host Daemon)

Rust binary running as root under systemd.

**Responsibilities:**
- Listen on Unix socket `/run/build-service.sock`
- Extract caller UID/GID from `SO_PEERCRED`
- Validate requests (paths, args, timeouts)
- Drop privileges to caller’s user (UID/GID + supplementary groups)
- Execute `/usr/bin/make` directly (no shell)
- Stream output back as NDJSON
- Enforce timeouts and terminate process groups cleanly

### 2. build-cli (Container Client)

Rust binary installed in container images.

**Responsibilities:**
- Connect to `/run/build-service.sock`
- Send build request (cwd, args, timeout)
- Receive NDJSON stream, write to stdout/stderr
- Exit with build’s exit code

### 3. make wrapper (Container)

Shell script installed earlier in `PATH` than `/usr/bin/make`.

```sh
#!/bin/sh
exec build-cli make "$@"
```

> Note: Keeping this wrapper POSIX (`/bin/sh`) avoids relying on bash being present in minimal images.

## Configuration

Follow acl-proxy conventions: TOML config with schema versioning.

**Location:** `/etc/build-service/config.toml`

```toml
schema_version = "1"

[service]
socket_path = "/run/build-service.sock"
socket_group = "users"
socket_mode = "0660"

[build]
workspace_root = "/home"
make_path = "/usr/bin/make"

[build.timeouts]
default_sec = 600       # 10 minutes
max_sec = 1800          # 30 minutes (cap client requests)

[build.environment]
# Strict allowlist - only these env vars passed to make
allow = [
    "PATH",
    "HOME",
    "USER",
    "LANG",
    "CC",
    "CXX",
    "CFLAGS",
    "CXXFLAGS",
    "LDFLAGS",
    "PKG_CONFIG_PATH",
    "MAKEFLAGS",
]

[logging]
level = "info"
directory = "/var/log/build-service"
max_bytes = 104857600   # 100MB
max_files = 5
console = false
```

**Implementation note (socket permissions):**
- The daemon should create the socket with a restrictive umask (e.g., `0077`), bind it, then apply `chgrp`/`chmod` based on `socket_group`/`socket_mode`.
- Alternatively, place the socket under a systemd-managed runtime directory (see Deployment notes) to make permissions more predictable.

## Protocol

### Request (JSON)

```json
{
    "command": "make",
    "args": ["-j4", "all"],
    "cwd": "/home/kevin/workspace/app",
    "timeout_sec": 600
}
```

**Recommended additions (forward compatibility):**
- `schema_version`: match config schema (e.g., `"1"`)
- `request_id`: client-generated UUID for log correlation

### Response Stream (NDJSON)

```json
{"type": "stdout", "data": "gcc -c ..."}
{"type": "stderr", "data": "warning: ..."}
{"type": "exit", "code": 0, "timed_out": false}
```

**Binary/invalid UTF-8 output:** if the implementation must be lossless, add optional fields such as:
- `encoding`: `"utf-8"` or `"base64"`
- `data_b64`: base64-encoded bytes when output is not valid UTF-8

(If you keep `data` as a JSON string only, ensure invalid UTF-8 bytes are either rejected or converted in a clearly documented way.)

## Security

### Path Validation

- `cwd` must resolve under `/home/<peer_user>/workspace`
- `-C` / `--directory` directory args must not escape workspace
- `-f` / `--file` makefile args must not escape workspace
- Reject traversal that would escape (e.g., `..` components)
- Prefer validation using a canonicalized path rooted in the user’s workspace:
  - Use `std::fs::canonicalize()` for existing paths and reject anything that resolves outside the allowed root
  - Be explicit about symlink handling (canonicalization closes common symlink-escape issues)

### Privilege Drop

```rust
// After validation, before exec:
// 1. Get peer credentials
let cred = socket.peer_cred()?;

// 2. Initialize supplementary groups
initgroups(username, cred.gid)?;

// 3. Set GID then UID (order matters)
setgid(cred.gid)?;
setuid(cred.uid)?;

// 4. Exec make (never returns on success)
exec(make_path, args, env)?;
```

**Process-group handling (for reliable timeouts):**
- Spawn `make` into its own process group (e.g., via `setsid()` or `setpgid()` in a pre-exec hook)
- On timeout, signal the process group so child processes are terminated too

### No Shell Execution

```rust
// Direct exec, never:
//   Command::new("sh").arg("-c").arg(...)
// Always:
//   Command::new("/usr/bin/make").args(validated_args)
```

## Integration with aw-exec

Auto-mount the socket and workspace in containers:

```bash
# In aw-exec start_container()
podman run -d --replace     --name "$container_name"     --userns=keep-id     -v "$HOME/workspace:$HOME:Z"     -v /etc/localtime:/etc/localtime:ro     -v /etc/bashrc:/etc/bashrc:ro     -v /run/build-service.sock:/run/build-service.sock     "$image" sleep infinity
```

## Timeout Handling

| Source | Value | Description |
|--------|-------|-------------|
| Client | `--timeout` | CLI flag, passed in request |
| Config | `default_sec` | Used if client omits timeout |
| Config | `max_sec` | Hard cap on any client value |

On timeout:
1. Send `SIGTERM` to the **process group**
2. Wait 5 seconds
3. Send `SIGKILL` if still running
4. Emit: `{"type": "exit", "code": 124, "timed_out": true}`
5. Log: `build timed out after {N}s user={user} cwd={cwd}`

## Logging

Plain text format via `tracing` (matching acl-proxy style):

```
2026-01-14T12:00:00.000Z  INFO build_service: build started user=kevin cwd=/home/kevin/workspace/app args=["-j4","all"]
2026-01-14T12:00:30.000Z  INFO build_service: build completed user=kevin exit_code=0 duration_sec=30
2026-01-14T12:00:30.000Z ERROR build_service: build completed user=kevin exit_code=2 duration_sec=30
2026-01-14T12:01:00.000Z  WARN build_service: build timed out user=kevin duration_sec=600
```

> Note: log levels are a policy choice; this suggests non-zero exit codes as `ERROR` for easier alerting.

## Deployment

### Systemd Service

**File:** `/etc/systemd/system/build-service.service`

```ini
[Unit]
Description=Build Service
After=local-fs.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/build-service --config /etc/build-service/config.toml
Restart=on-failure
User=root

# Optional hardening (tune as needed):
# NoNewPrivileges=true
# PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

**Operational note:** If you want systemd to manage a runtime directory for the socket (recommended), consider updating `socket_path` to something like `/run/build-service/build-service.sock` and then add:

```ini
RuntimeDirectory=build-service
RuntimeDirectoryMode=0750
```

The daemon would then bind the socket within that directory and apply the configured group/mode to the socket file.

### Installation

```bash
# Install binary
sudo cp build-service /usr/local/bin/
sudo chmod 755 /usr/local/bin/build-service

# Install config
sudo mkdir -p /etc/build-service
sudo cp config.toml /etc/build-service/

# Create log directory
sudo mkdir -p /var/log/build-service

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable build-service
sudo systemctl start build-service
```

### Container Image Updates

Add to base Dockerfiles:

```dockerfile
# Build CLI and make wrapper
COPY build-cli /usr/local/bin/build-cli
COPY make-wrapper.sh /usr/local/bin/make
RUN chmod 755 /usr/local/bin/build-cli /usr/local/bin/make
```

## CLI Usage

```bash
# From within container - transparent via wrapper
make -j4 all

# Explicit CLI usage
build-cli make -j4 all
build-cli --timeout 1800 make clean all

# Check service status (from host)
systemctl status build-service
```

### Optional: sample .bashrc aliases

If you want an easy “always route through the service” behavior (even if the wrapper isn’t installed), add to the container image or user profile:

```bash
# Route make through build-cli if available
if command -v build-cli >/dev/null 2>&1; then
  alias make='build-cli make'
fi
```

## Error Handling

| Error | CLI Exit Code | Message |
|-------|---------------|---------|
| Socket not found | 1 | `build-service socket not found at /run/build-service.sock` |
| Connection refused | 1 | `cannot connect to build-service` |
| Protocol/serialization error | 1 | `invalid response from build-service` |
| Path validation | 1 | `cwd must be under workspace` |
| Build failure | N | (exit code from make) |
| Timeout | 124 | `build timed out after {N}s` |

## Future Considerations

- Additional commands beyond `make` (cmake, ninja) if needed
- Build queue with concurrency limits
- Resource limits (cgroups) per build
- Build caching integration
- Optional request/response version negotiation (`schema_version`)

## Amendments (Post-Initial Requirements)

- Config now uses a command allowlist (`build.commands`) instead of a single `make_path`.
- Container-to-host workspace path mapping is configurable via `build.path_mapping` templates.
- Requests map container paths before validation to support non-identical mounts.
- Supplementary groups are preserved using peer group discovery for accurate permissions.
- Exit status mapping follows 128 + signal conventions for signal terminations.
- Added tests across config, protocol, validation, daemon, and CLI behavior.
