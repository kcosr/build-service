# Changelog

## [Unreleased]

### Breaking Changes
- Require schema v2 configuration and project-based builds; v1 socket protocol is no longer supported. ([#000](https://github.com/kcosr/build-service/pull/000))

### Added
- HTTP build endpoint with optional TLS and bearer auth plus NDJSON streaming. ([#000](https://github.com/kcosr/build-service/pull/000))
- Repo/path projects with artifact collection, download URLs, and GC support. ([#000](https://github.com/kcosr/build-service/pull/000))

### Changed
- build-cli supports HTTP endpoints, tokens, and project selection. ([#000](https://github.com/kcosr/build-service/pull/000))

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
