# Build Service Requirements

## Purpose

- Run host builds that depend on proprietary libraries not available in containers.
- Allow containerized agents to submit source and receive build artifacts.
- Preserve deterministic, auditable builds with strict command allowlists.

## Environment

- Host OS: Rocky Linux
- Container runtime: Podman (rootless)
- Socket access group: configurable (e.g., `users`)

## Architecture

```
┌─────────────────────┐         ┌──────────────────────┐
│  Container          │         │  Host                │
│                     │         │                      │
│  make (wrapper)     │─────────│  build-service       │
│       │             │ HTTP/UDS│       │              │
│       ▼             │         │       ▼              │
│  build-cli          │────────►│  Validate request    │
│                     │         │       │              │
│  Streams stdout/err │◄────────┼───────┤              │
│                     │         │       ▼              │
└─────────────────────┘         │  exec allowed cmd    │
                                │                      │
                                └──────────────────────┘
```

## Components

### 1) build-service (host daemon)

Responsibilities:
- Listen on HTTP (TCP) and/or HTTP-over-UDS.
- Enforce command allowlist and timeouts.
- Extract uploaded source into a temp workspace.
- Execute build command and stream NDJSON output.
- Collect artifacts into a single `artifacts.zip`.

### 2) build-cli (client)

Responsibilities:
- Read `.build-service/config.toml` from repo root.
- Package sources into a zip based on include/exclude patterns.
- Send multipart request (`metadata` + `source`) over HTTP or UDS.
- Stream NDJSON output to stdout/stderr.
- Download `artifacts.zip` and extract into repo root (overwrite).

### 3) make wrapper

POSIX shell wrapper installed earlier in `PATH` than `/usr/bin/make`:

```sh
#!/bin/sh
exec build-cli "$@"
```

## Configuration

### Server (host)

Location: `/etc/build-service/config.toml`

```toml
schema_version = "3"

[service.socket]
enabled = true
path = "/run/build-service.sock"
group = "users"
mode = "0660"

[service.http]
enabled = false
listen_addr = "0.0.0.0:8080"

[service.http.auth]
type = "bearer"
required = false
# tokens = ["<secret token>"]

[service.http.tls]
enabled = false
# cert_path = "/etc/build-service/tls/server.crt"
# key_path = "/etc/build-service/tls/server.key"
# ca_path = "/etc/build-service/tls/ca.crt"

[build]
workspace_root = "/var/lib/build-service/workspaces"
# run_as_user = "build"
# run_as_group = "build"
max_upload_bytes = 134217728
max_extracted_bytes = 1342177280

[build.commands]
make = "/usr/bin/make"

[build.timeouts]
default_sec = 600
max_sec = 1800

[build.environment]
allow = [
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "CC",
    "CXX",
    "CFLAGS",
    "CXXFLAGS",
    "LDFLAGS",
    "PKG_CONFIG_PATH",
    "MAKEFLAGS",
]

[artifacts]
storage_root = "/var/lib/build-service/artifacts"
# ttl_sec = 86400
# gc_interval_sec = 3600
# max_bytes = 1073741824
```

### Client (repo)

Location: `.build-service/config.toml`

```toml
[sources]
include = ["**/*"]
exclude = [".git/**", ".build-service/**", "target/**"]

[artifacts]
include = ["out/**", "dist/*.tar.gz"]
exclude = ["**/*.tmp"]

[connection]
# endpoint = "unix:///run/build-service.sock"
# endpoint = "https://build.example.com"
# token = "..."

[request]
# timeout_sec = 900

[request.env]
CC = "clang"
CFLAGS = "-O2 -g"
```

Notes:
- Endpoint must start with `http://`, `https://`, or `unix://`.
- Connection precedence: CLI flags > env vars > `.build-service/config.toml` > default endpoint (`unix:///run/build-service.sock`).
- Env overrides: `BUILD_SERVICE_ENDPOINT`, `BUILD_SERVICE_TOKEN`, `BUILD_SERVICE_TIMEOUT`.
- The wrapper falls back to the local command when `.build-service/config.toml` is missing.

## Protocol

### Start Build

`POST /v1/builds` (multipart)

Parts:
- `metadata` (JSON)
- `source` (zip)

Example metadata:

```json
{
  "schema_version": "3",
  "request_id": "<optional>",
  "command": "make",
  "args": ["-j4", "all"],
  "cwd": "subdir",
  "timeout_sec": 600,
  "artifacts": {"include": ["out/**"], "exclude": []},
  "env": {"CC": "clang"}
}
```

### Response Stream (NDJSON)

```json
{"type":"build","id":"bld_123","status":"started"}
{"type":"stdout","data":"..."}
{"type":"stderr","data":"..."}
{"type":"exit","code":0,"timed_out":false,
 "artifacts":{"path":"/v1/builds/bld_123/artifacts.zip","size":123456}}
```

### Artifact Download

`GET /v1/builds/{build_id}/artifacts.zip`

## Validation and Security

- `cwd` and all glob patterns must be relative (no `..` or absolute paths).
- Source archive extraction uses `enclosed_name()` to prevent zip-slip.
- Artifact paths are canonicalized and must stay under the build root.
- `make` args `-C`/`-f` are validated to prevent escapes.
- Commands are restricted to `build.commands` allowlist.
- HTTP auth tokens are optional and apply only to TCP HTTP (not UDS).
- Builds run as the service user by default or `build.run_as_user`/`build.run_as_group`.

## Timeout Handling

On timeout:
1. Send `SIGTERM` to the process group
2. Wait 5 seconds
3. Send `SIGKILL` if still running
4. Emit `{"type":"exit","code":124,"timed_out":true}`
