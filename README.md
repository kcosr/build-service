# Build Service

A host-side build service that executes `make` on the host when triggered from containers, while preserving the caller's identity via Unix socket peer credentials.

This exists to support builds that depend on proprietary host libraries that cannot be exposed inside containers used by coding agents or third-party hosted models.

## Components

- **build-service**: host daemon running as root under systemd. Validates requests, drops privileges, runs the configured command, and streams output.
- **build-cli**: container client that sends requests and relays NDJSON output to stdout/stderr.
- **make wrapper**: a POSIX shell shim that replaces `make` in containers.

## Architecture

```
+---------------------+         +----------------------+
|  Container          |         |  Host                |
|                     |         |                      |
|  make (wrapper)     |---------|  build-service       |
|       |             |  Unix   |       |              |
|       v             |  Socket |       v              |
|  build-cli ---------+-------->|  Validate request    |
|                     |         |       |              |
|  Streams stdout/err |<--------+-------+              |
|                     |         |       v              |
+---------------------+         |  Drop privs (peer)   |
                                |       |              |
                                |       v              |
                                |  exec configured cmd |
                                |                      |
                                +----------------------+
```

## Configuration

Sample config: `config/config.toml`

Key fields:
- `schema_version`: config schema version (currently "1").
- `service.socket_path`: Unix socket path.
- `service.socket_group`: group that can access the socket.
- `service.socket_mode`: octal permissions (e.g., "0660").
- `build.workspace_root`: base path expanded as `<workspace_root>/<username>/workspace`.
- `build.commands`: allowlist mapping `command` -> absolute binary path.
- `build.timeouts.default_sec`: default timeout.
- `build.timeouts.max_sec`: hard cap for client requests.
- `build.environment.allow`: allowlist of environment variables passed to the build.
- `logging.*`: log level and rotation settings.

Environment overrides:
- `BUILD_SERVICE_CONFIG`: alternate config path.
- `BUILD_SERVICE_LOG_LEVEL`: override `logging.level`.

## Protocol

### Request (JSON)

```
{
  "schema_version": "1",
  "request_id": "<optional>",
  "command": "make",
  "args": ["-j4", "all"],
  "cwd": "/home/user/workspace/project",
  "timeout_sec": 600
}
```

### Response Stream (NDJSON)

```
{"type":"stdout","data":"gcc -c ..."}
{"type":"stderr","data":"warning: ..."}
{"type":"exit","code":0,"timed_out":false}
```

Output is streamed as lossy UTF-8; invalid bytes are replaced.

## Path Validation

- `cwd` must resolve under `/home/<user>/workspace` (derived from config).
- `-C`/`--directory` and `-f`/`--file` args are resolved relative to the current directory and must stay under the workspace.
- Requests that escape the workspace are rejected.

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
# in container
build-cli make -j4 all
build-cli --timeout 1800 make clean all

# use a non-default socket path
build-cli --socket /run/build-service.sock make -n
```

Environment:
- `BUILD_SERVICE_SOCKET`: override socket path

## Make Wrapper

Install the wrapper earlier in `PATH` than `/usr/bin/make`:

```
cp scripts/make-wrapper.sh /usr/local/bin/make
chmod 755 /usr/local/bin/make
```

## Logging

Logs are written using `tracing` in a plain-text format. Configure log directory/rotation in `[logging]`.

## Notes

- The daemon must run as root to drop privileges to the calling user.
- Commands are restricted by `build.commands` allowlist.

## Roadmap

- Add configurable container-to-host path mapping for workspace mounts.
