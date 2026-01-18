# Build Service

A host-side build service that accepts source uploads from clients, runs an allowed command on the host, streams NDJSON output, and returns a single `artifacts.zip` that the client automatically extracts into the local workspace.

This exists to support builds that depend on proprietary host libraries that cannot be exposed inside containers used by coding agents or third-party hosted models.

## ⚠️ Security Considerations

This service intentionally bridges a container isolation boundary. Any process that can submit source archives and invoke build commands can run code on the host with the service's privileges (or the configured run-as user).

Before deploying, consider:
- **Who can reach the socket or HTTP endpoint** (group permissions, network exposure, reverse proxy rules)
- **Whether HTTP auth tokens are required** (`service.http.auth`)
- **What host resources** the run-as user can access (files, network, credentials)
- **Whether audit logging** and timeouts provide sufficient visibility and limits

If your environment includes untrusted or semi-trusted workloads, this service may not be appropriate.

## Components

- **build-service**: host daemon. Validates requests, extracts uploaded sources to a temp workspace, runs the configured command, streams output, and packages artifacts.
- **build-cli**: client that packages sources, sends requests (HTTP or UDS), relays NDJSON output, and extracts artifacts.
- **make wrapper**: a POSIX shell shim that replaces `make` in containers.

## Architecture

```
+---------------------+         +----------------------+
|  Client             |         |  Host                |
|                     |         |                      |
|  build-cli          |---------|  build-service       |
|   (HTTP / UDS)      |         |   validate request   |
|                     |         |          |           |
|  Streams stdout/err |<--------+----------+           |
|                     |         |          v           |
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
- Endpoint must start with `http://`, `https://`, or `unix://`.
- Connection precedence: CLI flags > env vars > `.build-service/config.toml` > default endpoint (`unix:///run/build-service.sock`).
- Env overrides: `BUILD_SERVICE_ENDPOINT`, `BUILD_SERVICE_TOKEN`.

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

## Make Wrapper

Install the wrapper earlier in `PATH` than `/usr/bin/make`:

```
cp scripts/make-wrapper.sh /usr/local/bin/make
chmod 755 /usr/local/bin/make
```

## Logging

Logs are written using `tracing` in a plain-text format. Configure log directory/rotation in `[logging]`.

## Notes

- Builds run as the service process user by default, or `build.run_as_user`/`build.run_as_group` if set.
- Artifacts are bundled into `artifacts.zip` and extracted by the client into the repo root.
