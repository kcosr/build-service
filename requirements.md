# Build Service

A host-side build service that executes configured commands for defined projects when triggered via Unix socket or HTTP, streaming NDJSON output and providing artifact downloads.

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

- Run host builds for projects defined in config (`repo` and `path`)
- Allow container and HTTP clients to trigger builds
- Stream stdout/stderr and structured exit status
- Provide artifact downloads via URLs in the NDJSON stream

## Environment

- Host OS: Rocky Linux
- Container runtime: Podman (rootless)
- Socket access group: configurable (e.g., `users`)

## Architecture

```
+---------------------+         +----------------------+
|  Client             |         |  Host                |
|                     |         |                      |
|  build-cli          |---------|  build-service       |
|   (socket/HTTP)     |         |   validate request   |
|                     |         |          |           |
|  Streams stdout/err |<--------+----------+           |
|                     |         |          v           |
+---------------------+         |   exec allowed cmd   |
                                |                      |
                                +----------------------+
```

## Components

### 1. build-service (Host Daemon)

Rust binary running under systemd.

**Responsibilities:**
- Listen on Unix socket and/or HTTP (configurable)
- Authenticate requests when enabled (bearer tokens)
- Resolve project roots (repo clone or path root)
- Validate request and arguments
- Execute allowed commands
- Stream NDJSON output and exit status
- Collect artifacts and expose download URLs
- Enforce timeouts

### 2. build-cli (Client)

Rust binary for container/host usage.

**Responsibilities:**
- Connect to socket or HTTP endpoint
- Send build request
- Receive NDJSON stream, write to stdout/stderr
- Exit with build’s exit code

### 3. make wrapper (Container)

Shell shim installed earlier in `PATH` than `/usr/bin/make`:

```sh
#!/bin/sh

if [ -z "$BUILD_SERVICE_PROJECT" ]; then
  echo "BUILD_SERVICE_PROJECT is not set" >&2
  exit 1
fi

exec build-cli --project "$BUILD_SERVICE_PROJECT" make "$@"
```

## Configuration

**Location:** `/etc/build-service/config.toml`

```toml
schema_version = "2"

[service.socket]
enabled = true
path = "/run/build-service.sock"
group = "users"
mode = "0660"

[service.http]
enabled = false
listen_addr = "0.0.0.0:8080"

[build]
workspace_root = "/home"
# run_as_user = "build"
# run_as_group = "build"

[build.commands]
make = "/usr/bin/make"

[artifacts]
storage_root = "/var/lib/build-service/artifacts"
public_base_url = "https://builds.example.com/artifacts"
# ttl_sec = 86400
# gc_interval_sec = 3600
# max_bytes = 1073741824

[[projects]]
id = "sip-stack"
type = "repo"
repo_url = "https://github.com/org/sip-stack.git"
repo_ref = "main"
repo_subdir = "./"
commands = ["make"]
artifacts = ["bin/app", "dist/*.tar.gz"]

[[projects]]
id = "nfs-tooling"
type = "path"
path_root = "/mnt/nfs/tooling"
commands = ["make", "ninja"]
artifacts = ["out/tool"]
```

## Protocol

### Request (JSON)

```json
{
  "schema_version": "2",
  "request_id": "<optional>",
  "project_id": "sip-stack",
  "command": "make",
  "args": ["-j4", "all"],
  "cwd": "subdir",
  "timeout_sec": 600,
  "ref": "feature/foo"
}
```

### Response Stream (NDJSON)

```json
{"type":"build","id":"bld_123","status":"started"}
{"type":"stdout","data":"gcc -c ..."}
{"type":"stderr","data":"warning: ..."}
{"type":"exit","code":0,"timed_out":false,
 "artifacts":[
   {"name":"bin/app","url":"https://builds.example.com/artifacts/bld_123/bin/app",
    "content_type":"application/octet-stream","size":123456}
 ]}
```

## Project Resolution

### Repo Project

1. Create a workspace under `build.workspace_root/builds/<build_id>`.
2. Clone `repo_url` and checkout `repo_ref` or request `ref` override.
3. Set project root to clone path + `repo_subdir`.
4. Validate `cwd` (if provided) is within project root.

### Path Project

1. Use `path_root` as project root.
2. Validate `cwd` (if provided) is within project root.

## Artifacts

- Artifact patterns are resolved relative to the project root.
- If any configured pattern matches nothing, artifact collection fails and the build exits non-zero.
- Directory matches are zipped and stored as `path.zip`.
- Stored artifacts live under `artifacts.storage_root/<build_id>/...`.
- Download URLs are `artifacts.public_base_url/<build_id>/<path>`.

## Security

### Auth

- HTTP uses bearer tokens (`Authorization: Bearer <token>`) when required.
- Unix socket can optionally require a token in the request body.
- Tokens are shared secrets; they do not map to user identities.

### Path Validation

- `cwd` must resolve under the project root.
- `-C` / `--directory` and `-f` / `--file` make args must not escape the project root.

### Privilege Drop

- Builds run as the service process user by default.
- Optional `build.run_as_user`/`build.run_as_group` override the execution user/group.

## Timeout Handling

On timeout:
1. Send `SIGTERM` to the process group
2. Wait 5 seconds
3. Send `SIGKILL` if still running
4. Emit `{"type":"exit","code":124,"timed_out":true}`

## Logging

Plain text format via `tracing`.

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

[Install]
WantedBy=multi-user.target
```

### Installation

```bash
sudo cp build-service /usr/local/bin/
sudo chmod 755 /usr/local/bin/build-service

sudo mkdir -p /etc/build-service
sudo cp config.toml /etc/build-service/

sudo mkdir -p /var/log/build-service

sudo systemctl daemon-reload
sudo systemctl enable build-service
sudo systemctl start build-service
```

### Container Image Updates

Add to base Dockerfiles:

```dockerfile
COPY build-cli /usr/local/bin/build-cli
COPY make-wrapper.sh /usr/local/bin/make
RUN chmod 755 /usr/local/bin/build-cli /usr/local/bin/make
```

## Future Considerations

- Per-project resource limits (cgroups)
- Build queue with concurrency limits
- Auth-to-user mapping for per-user builds
