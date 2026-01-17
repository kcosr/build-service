# Build Service

A host-side build service that runs configured build commands for defined projects, triggered via Unix socket and/or HTTP, and streams NDJSON output back to clients.

This exists to support builds that depend on proprietary host libraries that cannot be exposed inside containers used by coding agents or third-party hosted models.

## ⚠️ Security Considerations

This service intentionally bridges a container isolation boundary. Any process that can invoke the service can run commands on the host with the service’s privileges (or the configured run-as user).

Before deploying, consider:
- **Who can reach the socket or HTTP endpoint** (group permissions, network exposure, reverse proxy rules)
- **Whether auth tokens are required** (`service.http.auth` / `service.socket.auth`)
- **What host resources** the run-as user can access (files, network, credentials)
- **Whether audit logging** and timeouts provide sufficient visibility and limits

If your environment includes untrusted or semi-trusted workloads, this service may not be appropriate.

## Components

- **build-service**: host daemon. Validates requests, runs the configured command for a project, and streams output.
- **build-cli**: client that sends requests (socket or HTTP) and relays NDJSON output to stdout/stderr.
- **make wrapper**: a POSIX shell shim that replaces `make` in containers.

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

## Configuration

Sample config: `config/config.toml`

Key fields:
- `schema_version`: config schema version (currently "2").
- `service.socket.*`: Unix socket enablement, path, group, mode, and optional auth.
- `service.http.*`: HTTP enablement, listen address, auth, and optional TLS.
- `build.workspace_root`: base directory for repo project workspaces.
- `build.run_as_user` / `build.run_as_group`: optional run-as user/group.
- `build.commands`: allowlist mapping `command` -> absolute binary path.
- `build.timeouts.*`: default timeout and max timeout.
- `build.environment.allow`: allowlist of environment variables passed to the build.
- `artifacts.*`: artifact storage root, public base URL, TTL/GC settings.
- `projects`: list of `repo` and `path` projects with allowed commands and artifact patterns.

Environment overrides:
- `BUILD_SERVICE_CONFIG`: alternate config path.
- `BUILD_SERVICE_LOG_LEVEL`: override `logging.level`.

## Protocol

### Request (JSON)

```
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

```
{"type":"build","id":"bld_123","status":"started"}
{"type":"stdout","data":"gcc -c ..."}
{"type":"stderr","data":"warning: ..."}
{"type":"exit","code":0,"timed_out":false,
 "artifacts":[
   {"name":"bin/app","url":"https://builds.example.com/artifacts/bld_123/bin/app",
    "content_type":"application/octet-stream","size":123456}
 ]}
```

Output is streamed as lossy UTF-8; invalid bytes are replaced.

### Artifact Download

`GET /v1/builds/{build_id}/artifacts/{path}`

## Path Validation

- `cwd` must resolve under the project root.
- `-C`/`--directory` and `-f`/`--file` args are validated for `make` to prevent escapes.
- Repo `cwd` values can be relative (preferred) or absolute paths under the repo root.

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
# socket
build-cli --project sip-stack make -j4 all
build-cli --project sip-stack --timeout 1800 make clean all

# HTTP
build-cli --endpoint https://builds.example.com --token <token> \
  --project sip-stack make -j4 all

# repo ref override
build-cli --endpoint https://builds.example.com --token <token> \
  --project sip-stack --ref feature/foo make -j4 all
```

Environment:
- `BUILD_SERVICE_SOCKET`: override socket path
- `BUILD_SERVICE_ENDPOINT`: HTTP endpoint
- `BUILD_SERVICE_TOKEN`: auth token
- `BUILD_SERVICE_PROJECT`: default project for `build-cli`

## Make Wrapper

Install the wrapper earlier in `PATH` than `/usr/bin/make`:

```
cp scripts/make-wrapper.sh /usr/local/bin/make
chmod 755 /usr/local/bin/make
```

Set `BUILD_SERVICE_PROJECT` in the container environment so the wrapper can select a project.

## Logging

Logs are written using `tracing` in a plain-text format. Configure log directory/rotation in `[logging]`.

## Notes

- Builds run as the service process user by default, or `build.run_as_user`/`build.run_as_group` if set.
- Repo projects are cloned into `build.workspace_root/builds/<build_id>` and cleaned up after the build.
- Artifact glob misses fail the build and emit an `error` event.
