# Build Service

A build service that accepts source uploads from clients, runs an allowed command on the host, streams NDJSON output, and returns a single `artifacts.zip` that the client automatically extracts into the local workspace.

It can be used for builds that depend on proprietary host libraries that cannot be exposed inside containers, as well as for offloading builds to remote, more powerful servers or centralizing build tooling.

## ⚠️ Security Considerations

This service executes build commands on the host (or the configured run-as user). It includes basic guardrails, but it does not provide strong sandboxing. A build can still read or copy files outside the workspace if the service user has access. If that is a concern, run the service inside a container or a dedicated VM.

Built-in protections to review and tune:
- **Command allowlist** (`build.commands`)
- **Environment allowlist** (`build.environment.allow`)
- **Workspace isolation** (temp workspace per build, with relative path validation for sources/artifacts/cwd)
- **Upload size and timeouts** (`build.max_upload_bytes`, `build.timeouts`)
- **Transport controls** (socket permissions, optional HTTP auth)

If your environment includes untrusted or semi-trusted workloads, consider additional isolation around the service.

## Components

- **build-service**: host daemon. Validates requests, extracts uploaded sources to a temp workspace, runs the configured command, streams output, and packages artifacts.
- **build-cli**: client that packages sources, sends requests (HTTP or UDS), relays NDJSON output, and extracts artifacts.
- **build wrapper**: a POSIX shell shim that replaces build tools in containers.

## Architecture

```
+---------------------+         +----------------------+
|  Client             |         |  Host                |
|                     |         |                      |
|  build-cli          |-- source.zip --> build-service |
|   (HTTP / UDS)      |         |   validate request   |
|                     |<- NDJSON ------+               |
|                     |<- artifacts.zip+               |
|                     |         |      v               |
+---------------------+         |   exec allowed cmd   |
                                |                      |
                                +----------------------+
```

## Configuration

Sample config: `config/config.toml`

Key fields:
- `schema_version`: config schema version (currently "3").
- `service.socket.*`: Unix socket enablement, path, group, mode.
- `service.http.*`: HTTP enablement, listen address, auth, and optional TLS.
- `build.workspace_root`: base directory for temp workspaces.
- `build.max_upload_bytes`: max source upload size (default 128MB).
- `build.run_as_user` / `build.run_as_group`: optional run-as user/group.
- `build.commands`: allowlist mapping `command` -> absolute binary path.
- `build.timeouts.*`: default timeout and max timeout.
- `build.environment.allow`: allowlist of environment variables passed to the build.
- `artifacts.storage_root`: artifact storage root (per-build subdirs).
- `artifacts.*`: TTL/GC settings for artifact retention.

Environment overrides:
- `BUILD_SERVICE_CONFIG`: alternate config path.
- `BUILD_SERVICE_LOG_LEVEL`: override `logging.level`.

## Repo-local Client Config

File: `.build-service/config.toml`

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
# optional defaults
# timeout_sec = 900

[request.env]
CC = "clang"
CFLAGS = "-O2 -g"
```

Notes:
- `sources` and `artifacts` patterns must be relative and cannot use `..`.
- The CLI refuses to run if `.build-service/config.toml` is missing.
- The wrapper falls back to the local command when `.build-service/config.toml` is missing.
- Endpoint must start with `http://`, `https://`, or `unix://`.
- Connection precedence: CLI flags > env vars > `.build-service/config.toml` > default endpoint (`unix:///run/build-service.sock`).
- Env overrides: `BUILD_SERVICE_ENDPOINT`, `BUILD_SERVICE_TOKEN`, `BUILD_SERVICE_TIMEOUT`.

## Protocol

### Start Build (multipart)
`POST /v1/builds` over TCP or Unix socket (HTTP over UDS)
`Authorization: Bearer <token>` when HTTP auth is enabled.

`multipart/form-data` parts:
- `metadata` (application/json)
- `source` (application/zip)

Metadata JSON:

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
Streamed as `application/x-ndjson` until exit.

```json
{"type":"build","id":"bld_123","status":"started"}
{"type":"stdout","data":"..."}
{"type":"stderr","data":"..."}
{"type":"exit","code":0,"timed_out":false,
 "artifacts":{"path":"/v1/builds/bld_123/artifacts.zip","size":123456}}
```

On artifact collection failure:

```json
{"type":"error","code":"artifact_glob_miss","pattern":"dist/*.tar.gz"}
{"type":"exit","code":1,"timed_out":false}
```

### Artifact Download
`GET /v1/builds/{build_id}/artifacts.zip`

## Path Validation

- `cwd` and all glob patterns must be relative and cannot contain `..`.
- `-C`/`--directory` and `-f`/`--file` args are validated for `make` to prevent escapes.
- Source extraction and artifact paths are canonicalized to prevent traversal.

## Timeout Handling

On timeout:
1. Send `SIGTERM` to the process group
2. Wait 5 seconds
3. Send `SIGKILL` if still running
4. Emit `{"type":"exit","code":124,"timed_out":true}`

## Build and Install

Build locally:

```
cargo build --release
```

Install on host:

```
sudo cp target/release/build-service /usr/local/bin/
sudo mkdir -p /etc/build-service
sudo cp config/config.toml /etc/build-service/config.toml
sudo mkdir -p /var/log/build-service
sudo cp systemd/build-service.service /etc/systemd/system/build-service.service
sudo systemctl daemon-reload
sudo systemctl enable --now build-service
```

## CLI Usage

```
# Unix socket (default)
build-cli make -j4 all
build-cli --timeout 1800 make clean all

# HTTP
build-cli --endpoint https://builds.example.com --token <token> make -j4 all
```

Environment:
- `BUILD_SERVICE_ENDPOINT`: endpoint URL (`http://`, `https://`, or `unix://`)
- `BUILD_SERVICE_TOKEN`: bearer token (HTTP only)
- `BUILD_SERVICE_TIMEOUT`: timeout in seconds

## Build Wrapper

Install the wrapper earlier in `PATH` than the real build tools:

```
cp scripts/build-wrapper.sh /usr/local/bin/build-wrapper
chmod 755 /usr/local/bin/build-wrapper
```

The wrapper runs `build-cli` with the command name it was invoked as (for example `make` or `cargo`). If no repo-local config is found, it executes the local command instead.

## Logging

Logs are written using `tracing` in a plain-text format. Configure log directory/rotation in `[logging]`.

## Notes

- Builds run as the service process user by default, or `build.run_as_user`/`build.run_as_group` if set.
- Artifacts are bundled into `artifacts.zip` and extracted by the client into the repo root.
