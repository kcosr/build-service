# Feature/Improvement Design: Disable build-service via client config

## Overview
Add a boolean toggle to the repo-local client config (`.build-service/config.toml`) that causes the wrapper to **not use build-service** and instead execute the local tool. This provides a config-file equivalent of the existing `BUILD_SERVICE_ENABLED=false` wrapper override.

## Motivation
- Some environments prefer a persistent, repo-scoped setting instead of requiring a per-shell/per-CI env var.
- Matches the existing “escape hatch” behavior of `BUILD_SERVICE_ENABLED=false`.

## Proposed Solution

### New setting
Add a new field under `[connection]`:

```toml
[connection]
# When false, build-cli exits with the wrapper fallback exit code (222),
# causing build-wrapper to run the local build tool.
enabled = true
```

Why `[connection]`? The toggle effectively controls whether we attempt any remote connection at all, and it fits naturally next to `endpoint`, `token`, and `local_fallback`.

### Precedence
Resolve `enabled` as:
1. `BUILD_SERVICE_ENABLED` env var **when set** (highest priority)
2. `.build-service/config.toml` (`connection.enabled`)
3. default: `true`

This preserves the ability to force-enable/disable from CI/shell without editing the repo config.

### Behavior when disabled
In `build-cli`:
- If resolved `enabled == false`:
  - Print a short message to stderr (e.g. `"[build-service] disabled (BUILD_SERVICE_ENABLED/connection.enabled)"`).
  - Exit with code **222**.

Rationale: `build-wrapper.sh` already treats `222` as “fall back to local tool”, so this integrates cleanly without teaching the shell wrapper to parse TOML.

Notes:
- This “222 means fallback” becomes slightly broader than “connection failed” (it includes “explicitly disabled”). Update wrapper comment/docs accordingly.
- `connection.local_fallback` remains meaningful for *connection failure* behavior; the explicit disable should always return 222 so the wrapper reliably falls back.

### Documentation updates
- Update README and requirements to mention `connection.enabled = false` as an alternative to `BUILD_SERVICE_ENABLED=false`.
- Update the repo-local config snippet to include the new key.

## Files to Update
- `src/bin/build-cli.rs`
  - Extend `ConnectionConfig` with `enabled: bool` (default true)
  - Add env var parsing for `BUILD_SERVICE_ENABLED`
  - Early-exit with code 222 when disabled
- `README.md`
  - Add `connection.enabled` to the config snippet
  - Mention it in Notes next to `BUILD_SERVICE_ENABLED`
- `requirements.md`
  - Mention `connection.enabled` in Notes
- `scripts/build-wrapper.sh`
  - Update the comment about exit code 222 to include “explicitly disabled” (optional but recommended)
- `tests/build_cli_connection.rs`
  - Add a test that `connection.enabled = false` returns 222

## Implementation Steps
1. Add `enabled` to `ConnectionConfig` with `#[serde(default = "default_true")]` or a `bool` with a custom default (since Rust `bool` defaults to false).
2. Add `BUILD_SERVICE_ENABLED` parsing in `build-cli` (match wrapper semantics: treat empty/0/false/no/off as disabled; anything else as enabled).
3. Compute `enabled` early in `main()` after reading config, before packaging sources.
4. If disabled: print message and return `ExitCode::from(222)`.
5. Update README/requirements and the wrapper comment.
6. Add/adjust tests.

## Decisions
- Target config: repo-local client config (`.build-service/config.toml`).
- Key: `connection.enabled` (default true).

## Open Questions
- None.

## Alternatives Considered
- Teach `build-wrapper.sh` to parse TOML directly (fragile; extra dependency on `tomlq/jq/python`).
- Add a separate config file (more complexity; less discoverable).

## Out of Scope
- Adding a CLI flag like `--no-build-service` (could be added later, but not required for parity with env/config).
