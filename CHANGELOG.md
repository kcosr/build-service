# Changelog

## [Unreleased]

_No unreleased changes._

## [0.5.2] - 2026-06-26

### Added
- Add server-side `artifacts.restricted_patterns` to omit configured artifact paths from archives and report path-free restriction metadata to clients ([#17](https://github.com/kcosr/build-service/pull/17)).

### Fixed
- Fixed release script cleanup handling after successful GitHub release creation.
- Improved release-script diagnostics and changelog validation edge cases.

## [0.5.1] - 2026-06-03

### Breaking Changes
- `build-cli` now requires the explicit `build` subcommand for build requests; use `build-cli build <command>` instead of `build-cli <command>`. Wrapper scripts should call `build-cli build "$cmd" "$@"` ([#15](https://github.com/kcosr/build-service/pull/15)).

### Added
- Add `POST /v1/workspaces/{id}/reset` and `DELETE /v1/workspaces/{id}` HTTP endpoints, with matching `build-cli workspace reset` and `build-cli workspace delete` subcommands, for manual lifecycle management of managed reusable workspaces ([#15](https://github.com/kcosr/build-service/pull/15)).

### Changed
- Managed reusable workspace source extraction now removes manifest-tracked source files that are absent from the latest source archive while preserving generated files and build outputs ([#15](https://github.com/kcosr/build-service/pull/15)).
- Release automation now creates normal GitHub releases ([#16](https://github.com/kcosr/build-service/pull/16)).
- Release version bumping is now handled inside the single release script, matching sibling Rust release tooling ([#16](https://github.com/kcosr/build-service/pull/16)).
- Release script now supports `current` and explicit stable version arguments, with clean-main, origin/main sync, authenticated GitHub CLI, and free-tag preconditions ([#16](https://github.com/kcosr/build-service/pull/16)).
- Hardened release version validation, local and remote tag checks, release recovery instructions, and release-script cleanup paths ([#16](https://github.com/kcosr/build-service/pull/16)).
- Documented release download/install guidance and Linux x86_64 plus macOS ARM64 archive packaging, with source builds moved to the development workflow ([#16](https://github.com/kcosr/build-service/pull/16)).

## [0.5.0] - 2026-03-24

### Breaking Changes
- Require a configured default workspace or explicit reusable workspace request for builds that do not use `workspace.reuse`, and drop the old implicit ephemeral-workspace path ([#14](https://github.com/kcosr/build-service/pull/14))
- Move source archive limits from `[build]` to `[sources]` as `max_transfer_bytes` and `max_uncompressed_bytes`, and define artifact request limits as `artifacts.max_transfer_bytes` / `artifacts.max_uncompressed_bytes` ([#14](https://github.com/kcosr/build-service/pull/14))

### Added
- Add `build.default_workspace_path`, optional source uploads, env-only wrapper mode, and CLI/env pattern overrides for `build-cli` ([#14](https://github.com/kcosr/build-service/pull/14))
- Add symmetric source and artifact transfer/content limits via `[sources].max_transfer_bytes`, `[sources].max_uncompressed_bytes`, `artifacts.max_transfer_bytes`, and `artifacts.max_uncompressed_bytes` ([#14](https://github.com/kcosr/build-service/pull/14))

### Changed
- Make `.build-service/config.toml` optional for `build-cli`; it now layers config file, env vars, and CLI flags, and only requires an explicit endpoint when no client config file is present ([#14](https://github.com/kcosr/build-service/pull/14))
- Make `service.socket.group` optional; when omitted, the daemon leaves socket group ownership unchanged and only applies the configured mode ([#14](https://github.com/kcosr/build-service/pull/14))

### Fixed
- Fix the `initgroups` call on macOS by using the Apple-specific parameter type in the pre-exec credential setup path ([#14](https://github.com/kcosr/build-service/pull/14))

## [0.4.4] - 2026-03-09

### Added
- Support `{repo}` macro expansion for workspace IDs in the CLI (`workspace.id` and `BUILD_SERVICE_WORKSPACE_ID`) ([#13](https://github.com/kcosr/build-service/pull/13)).

## [0.4.3] - 2026-03-09

### Added
- Add opt-in `build-cli` log capture with per-build `stdout.log` / `stderr.log`, path-based suppression notices, and final saved-log reporting ([#11](https://github.com/kcosr/build-service/pull/11)).

### Changed
- Make `build-cli` read HTTPS CA certificates from the OS trust store at runtime by switching `reqwest` to `rustls-tls-native-roots` ([#12](https://github.com/kcosr/build-service/pull/12)).

## [0.4.2] - 2026-03-05

### Added
- Support `{uid}` macro expansion for workspace IDs in the CLI (`workspace.id` and `BUILD_SERVICE_WORKSPACE_ID`) ([#10](https://github.com/kcosr/build-service/pull/10)).

## [0.4.1] - 2026-02-08

### Added
- Add `connection.enabled` to disable build-service usage via client config ([#9](https://github.com/kcosr/build-service/pull/9)).

## [0.4.0] - 2026-01-29

### Added
- Support `{branch}` macro expansion for workspace IDs with server-side sanitization ([#8](https://github.com/kcosr/build-service/pull/8)).

## [0.3.0] - 2026-01-20

### Added
- Workspace reuse support with client-supplied IDs, refreshable source sync, and TTL-based GC ([#7](https://github.com/kcosr/build-service/pull/7)).

## [0.2.0] - 2026-01-20

### Added
- Add client-configured stdout/stderr line limits with optional tail summaries and env overrides ([#6](https://github.com/kcosr/build-service/pull/6)).
- Cancel builds when clients disconnect from the output stream ([#6](https://github.com/kcosr/build-service/pull/6)).
- Return a fallback exit code when `connection.local_fallback` is enabled and the endpoint is unreachable ([#6](https://github.com/kcosr/build-service/pull/6)).

### Fixed
- Skip source include patterns that match no files instead of failing packaging ([#6](https://github.com/kcosr/build-service/pull/6)).

## [0.1.1] - 2026-01-18

### Changed
- Artifact patterns that match no files are now skipped instead of failing the build. This allows `make clean` and similar builds that don't produce artifacts to succeed ([#4](https://github.com/kcosr/build-service/pull/4)).

### Fixed
- Fixed "error decoding response body" on Unix socket connections by disabling HTTP keep-alive for streaming responses ([#4](https://github.com/kcosr/build-service/pull/4)).

### Added
- Unix file permissions are now preserved in source and artifact archives ([#4](https://github.com/kcosr/build-service/pull/4)).

## [0.1.0] - 2026-01-18

### Breaking Changes
- Replace project/path-based builds with source uploads and temp workspaces; `.build-service/config.toml` is now required and artifacts are returned as a single zip extracted by the CLI ([#3](https://github.com/kcosr/build-service/pull/3)).
- Require explicit endpoint schemes (`http://`, `https://`, `unix://`) and drop `--socket`/`BUILD_SERVICE_SOCKET` in favor of `BUILD_SERVICE_ENDPOINT` ([#3](https://github.com/kcosr/build-service/pull/3)).

### Added
- HTTP and Unix socket transports for multipart source uploads with NDJSON streaming and artifact download endpoints ([#3](https://github.com/kcosr/build-service/pull/3)).
- Generic build wrapper with local fallback; deploy via symlinks per build tool name ([#3](https://github.com/kcosr/build-service/pull/3)).
- Integration tests for HTTP/UDS build flows plus unit tests for endpoint/timeout parsing ([#3](https://github.com/kcosr/build-service/pull/3)).
- Add `build.max_extracted_bytes` to cap source extraction size ([#3](https://github.com/kcosr/build-service/pull/3)).

### Changed
- Build artifacts are packaged into a single `artifacts.zip` and automatically extracted by the client ([#3](https://github.com/kcosr/build-service/pull/3)).
- Client configuration supports explicit connection settings and timeout overrides via `BUILD_SERVICE_TIMEOUT` ([#3](https://github.com/kcosr/build-service/pull/3)).

### Removed
- Project-based build configuration and container-to-host path mapping mode ([#3](https://github.com/kcosr/build-service/pull/3)).

## [0.0.3] - 2026-01-14

### Changed
- Use `Cargo.toml` as single source of truth for versioning, remove `VERSION` file.

### Documentation
- Make `CLAUDE.md` a symlink to `AGENTS.md`.

## [0.0.2] - 2026-01-14

### Added
- Configurable container-to-host path mapping for workspace mounts. (#1)

### Changed
- Allow passing make flags (like `-f`) without requiring `--` in build-cli. (#1)

### Documentation
- Add AGENTS.md, link CLAUDE.md, and document post-requirements changes. (#1)

## [0.0.1] - 2026-01-14

### Added
- Initial build-service daemon, CLI, configuration, logging, wrapper, and documentation.
