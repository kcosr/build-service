# Changelog

## [Unreleased]

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
