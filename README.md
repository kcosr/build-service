# Build Service

A host-side build service that executes `make` on the host when triggered from containers, while preserving the caller's identity via Unix socket peer credentials.

This exists to support builds that depend on proprietary host libraries that cannot be exposed inside containers used by coding agents or third-party hosted models.

## ⚠️ Security Considerations

This service intentionally bridges a container isolation boundary. Any process with write access to the mounted workspace directory can create a Makefile (or modify an existing one) and trigger its execution on the host via this service. Build commands run with the peer user's privileges, meaning they could use a deliberately constructed Makefile to access files and resources on the host that are not exposed inside the container.

This is a trade-off. The alternative—exposing proprietary libraries inside containers accessible to third-party models—may carry greater risk depending on your threat model. If you trust the code and agents operating within your containers, or have other controls in place (network isolation, restricted user permissions, auditing), this service provides a pragmatic way to support host-dependent builds without broadening container access.

Before deploying, consider:
- **Who has write access** to workspace directories mounted into containers
- **What host resources** the peer user can reach (files, network, credentials)
- **Whether audit logging** and timeouts provide sufficient visibility and limits

If your environment includes untrusted or semi-trusted workloads with write access to mounted paths, this service may not be appropriate.

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
- `build.workspace_root`: base path used by `{workspace_root}` in path templates.
- `build.path_mapping.container_template`: container-side workspace root template (`{user}`, `{workspace_root}`).
- `build.path_mapping.host_template`: host-side workspace root template (`{user}`, `{workspace_root}`).
- `build.commands`: allowlist mapping `command` -> absolute binary path.
- `build.timeouts.default_sec`: default timeout.
- `build.timeouts.max_sec`: hard cap for client requests.
- `build.environment.allow`: allowlist of environment variables passed to the build.
- `logging.*`: log level and rotation settings.

Environment overrides:
- `BUILD_SERVICE_CONFIG`: alternate config path.
- `BUILD_SERVICE_LOG_LEVEL`: override `logging.level`.

Path mapping templates support `{user}` and `{workspace_root}` (`host_template` must include `{user}`). Defaults keep host and container paths identical; to map container `/home/<user>` to host `/home/<user>/workspace`, set `build.path_mapping.container_template = "/home/{user}"` and keep `build.path_mapping.host_template = "{workspace_root}/{user}/workspace"`.

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

- `cwd` is mapped from container paths to host paths using `build.path_mapping.*`, then must resolve under the host workspace root.
- `-C`/`--directory` and `-f`/`--file` args are resolved relative to the mapped cwd and must stay under the host workspace root.
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

- Support multiple workspace mappings for additional mounts.
