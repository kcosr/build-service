# Build CLI Log Capture Design

Status: Locked

## 1. Purpose

Define a client-side design for preserving complete build output in log files while keeping terminal output limits in place for `build-cli`.

## 2. Problem Statement

`build-cli` currently truncates streamed `stdout` and `stderr` after configurable line limits and prints a rerun hint that points users at `BUILD_SERVICE_STDOUT_MAX_LINES` and `BUILD_SERVICE_STDERR_MAX_LINES`. This keeps terminal output bounded, but it drops most of the build transcript from the default user experience and forces a rerun when full logs are needed. The feature should retain full output automatically, expose the saved log paths, and keep the existing limit controls available.

## 3. Goals

- Preserve complete `stdout` and `stderr` output for each streamed build in local log files.
- Keep terminal line limiting and tail summaries intact.
- Add client config to enable log capture and optionally override the base log directory.
- Default log storage to the system temp directory under a `build-service` namespace.
- Use the server-generated build ID to organize log files per build.
- Replace the current rerun hint with a concise notice that points to saved logs.

## 4. Non-Goals

- No server-side logging or protocol changes.
- No changes to artifact download semantics.
- No attempt to reconstruct a stronger cross-stream ordering than the NDJSON event order already seen by the client.
- No cleanup daemon or retention policy beyond writing logs into a predictable directory structure.
- No new environment variables in the first iteration.

## 5. Current Baseline

- Output limiting is implemented entirely in `src/bin/build-cli.rs`.
- `OutputLimiter` owns one `LineLimiter` per stream and writes directly to local `stdout` and `stderr`.
- `LineLimiter::write_chunk` prints the suppression notice that currently references the env-var rerun path.
- `read_responses` parses `ResponseEvent` items and ignores the `build` event payload today.
- The protocol already emits a unique build ID in the initial `{"type":"build","id":"..."}` event.

## 6. Key Decisions

1. Keep the feature in `build-cli`, because truncation and user-facing output are client-side concerns.
2. Add two output config keys under `[output]`:
   - `capture_logs = false` by default
   - `log_dir = "<optional path>"`
3. When `capture_logs = true`, write:
   - `<base>/<build_id>/stdout.log`
   - `<base>/<build_id>/stderr.log`
4. Default `<base>` to `std::env::temp_dir().join("build-service")` when `log_dir` is unset.
5. Capture the build ID from the streamed `build` event and create the per-build directory before handling later stream events.
6. Continue applying line limits only to terminal output, not to the log files.
7. Replace the suppression notice text so it points to the saved log file path for the affected stream instead of telling the user to rerun with an env var.
8. Retain the existing output-limit config and env-var overrides, because they still control terminal verbosity.
9. Resolve relative `log_dir` paths against the current run directory of the `build-cli` process when the run starts.
10. Emit a final completion notice with both saved log paths whenever capture is enabled and the log sink was initialized successfully, even if no suppression occurred.
11. Use standard cross-platform file creation APIs in v1 and avoid platform-specific permission manipulation.

## 7. Contract / HTTP Semantics

- No HTTP endpoint changes.
- No request payload changes.
- No response payload changes.
- `build-cli` will begin consuming the existing `ResponseEvent::Build { id, status }` payload instead of discarding it.

## 8. Service / Module Design

### Config model

- Extend `OutputConfig` with:
  - `capture_logs: bool`
  - `log_dir: Option<String>`
- Extend `OutputLimits` with:
  - `capture_logs: bool`
  - `log_dir: Option<PathBuf>` or equivalent normalized representation

### Log capture flow

1. `main()` resolves output settings from client config.
2. `read_responses()` tracks the build ID from the initial `build` event.
3. When log capture is enabled and the build ID is known, initialize a log sink rooted at:
   - configured `log_dir`, or
   - `temp_dir()/build-service`
4. For each `stdout` event:
   - append raw data to `stdout.log`
   - pass the same data to the terminal limiter
5. For each `stderr` event:
   - append raw data to `stderr.log`
   - pass the same data to the terminal limiter
6. `OutputLimiter` owns optional late-bound stream log path context and exposes a setter once the build ID is known; `LineLimiter` reads that state when it emits the suppression notice.
7. If `stdout` or `stderr` events arrive before the `build` event, buffer those early event chunks in memory, initialize the log sink when the build ID arrives, then drain the buffered chunks into the correct log file and terminal limiter in original event order.
8. If the `build` event never arrives, continue terminal output handling, emit a single warning that log capture could not be initialized, and abandon log capture for that run.
9. Final summary output remains terminal-only, followed by a single completion notice that lists the saved log paths when capture is active.

### Writer behavior

- Use buffered file writers for `stdout.log` and `stderr.log`.
- Flush after each streamed event write so logs remain useful during long-running builds and partial data loss is bounded if the client exits unexpectedly.
- Logged stream payloads are UTF-8 text because `ResponseEvent::{Stdout,Stderr}` carry `String` data.

### Path handling

- Configured `log_dir` is resolved as a filesystem path string.
- Relative `log_dir` values are resolved against the current run directory of the `build-cli` process when the run starts.
- Default path uses the OS temp dir API, not a hardcoded `"/tmp"` string.
- Per-build subdirectories are created lazily when the build event arrives.
- Build IDs are assumed unique because the server generates them from UUIDs; if a target directory already exists, the current invocation truncates and rewrites `stdout.log` and `stderr.log`.
- User-facing docs must call out that temp-dir retention is OS-managed and may be short-lived.

## 9. Error Semantics

- If log capture is disabled, behavior is unchanged.
- If log capture is enabled but the build event never arrives, continue normal output handling, emit a single warning that log capture could not be initialized, and do not treat the run as a protocol error solely for that reason.
- If log directory creation or file writes fail:
  - do not fail the build request outright,
  - continue terminal output handling,
  - print a single warning to `stderr` explaining that log capture was unavailable,
  - abandon further log capture for that run after the first persistent failure, including mid-stream `ENOSPC` or permission errors,
  - retain the existing env-var-oriented suppression notice as a fallback for that run.

## 10. Migration Strategy

- New config is additive and backward-compatible.
- Existing configs continue to work unchanged.
- Users can opt in by adding:

```toml
[output]
capture_logs = true
# log_dir = "/tmp/build-service"
```

- README and requirements should document the new behavior and clarify that output-limit env vars still affect terminal output only.

## 11. Test Strategy

- Unit tests for config resolution:
  - default disabled behavior
  - explicit `capture_logs = true`
  - explicit `log_dir`
- Unit tests for log-capture behavior:
  - build event initializes per-build paths
  - early `stdout` / `stderr` events buffer until the build ID is known
  - missing build event abandons capture with a warning
  - `stdout` and `stderr` are written to separate files
  - suppression notice points to the saved log path when capture is active
  - final completion notice prints saved paths even when no suppression occurs
  - failure to create/write logs warns once and falls back to the existing suppression hint
- Focused integration coverage for the `read_responses` loop using a mock NDJSON stream and real temp files.
- Regression coverage for current limiter behavior when capture is disabled.
- Full validation with `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo build --release`.

## 12. Acceptance Criteria

- With `capture_logs = false`, behavior matches current output limiting.
- With `capture_logs = true`, complete `stdout` and `stderr` are written for each build under a directory named by the build ID.
- The terminal still honors `stdout_max_lines`, `stderr_max_lines`, `stdout_tail_lines`, and `stderr_tail_lines`.
- When output is suppressed and logs are available, the user sees a notice pointing to the relevant saved log file.
- When capture succeeds, the user sees a final notice that identifies both saved log files for the build.
- README and requirements document the new config and updated suppression behavior.
- Tests cover config parsing, log creation, suppression messaging, and fallback behavior.

## 13. Review Notes

- Review outcome: keep `capture_logs` defaulted to `false` so the feature remains opt-in and additive.
- Review outcome: accept relative `log_dir` values and resolve them against the current run directory.
