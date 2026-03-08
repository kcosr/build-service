# Build CLI Log Capture Phase Task Plan

Status: Locked

## 1. Scope

Implement client-side log capture for `build-cli` so that complete per-build `stdout` and `stderr` are written to files while terminal output limits remain in force.

## 2. Global Rules

- Treat `docs/implementation/build-cli-log-capture/design.md` as the design source of truth.
- Do not change the wire protocol or server behavior.
- Preserve existing behavior when `output.capture_logs` is disabled.
- Keep the config key name free of the word `full`; use `capture_logs`.
- Prefer deterministic, offline tests.
- Before any commit: run `cargo fmt`, `cargo clippy`, `cargo test`, and `cargo build --release`.
- Update README and requirements in the same change set as code.

## 3. Phase H0: Contract Lock

### Deliverables

- Lock config names and default behavior.
- Lock the directory layout:
  - `<base>/<build_id>/stdout.log`
  - `<base>/<build_id>/stderr.log`
- Lock fallback behavior for log-capture failures.
- Lock relative-path semantics for `log_dir`.
- Lock early-stream buffering behavior for events that arrive before the build ID.

### Acceptance Criteria

- Design and task plan agree on config names, defaults, paths, and failure semantics.
- Any open review findings are triaged before implementation begins.

## 4. Phase H1: Config and Log Sink Plumbing

### Deliverables

- Extend output config parsing with `capture_logs` and `log_dir`.
- Extend `OutputLimits` and `OutputLimiter` with the capture settings and late-bound log-path state needed for suppression messaging.
- Introduce a small log sink state holder in `build-cli` for per-build writers.
- Capture the streamed build ID and initialize the per-build log directory.

### Acceptance Criteria

- `build-cli` can resolve effective log-capture settings from config.
- Log path resolution uses configured `log_dir` or system temp dir fallback.
- Relative `log_dir` values resolve against the current run directory of the `build-cli` process when the run starts.
- Build ID is captured from the streamed `build` event without changing protocol behavior.

## 5. Phase H2: Streaming Integration and User Messaging

### Deliverables

- Tee raw `stdout` and `stderr` event data into per-build log files.
- Buffer pre-build stream events until the build ID is known, then drain them into the log sink in original event order.
- Preserve existing terminal limiter behavior.
- Update suppression messaging to point at saved logs when available.
- Emit a final `stderr` completion notice with the saved log paths when capture succeeds.
- Preserve current env-var hint as fallback if logs cannot be created.

### Acceptance Criteria

- Terminal output still respects max-lines and tail-lines settings.
- Saved log files contain the complete stream data for each stream.
- Suppression messaging is path-based when log capture is active and healthy.
- Mid-stream log write failures downgrade to warning-and-fallback behavior without aborting the build.

## 6. Phase H3: Tests and Documentation

### Deliverables

- Add or update unit tests for config parsing, path resolution, log writing, and fallback behavior.
- Update README config snippet and notes.
- Update `requirements.md` to describe the new config and saved-log behavior.

### Acceptance Criteria

- Automated tests cover both enabled and disabled capture modes.
- Documentation matches the implemented config names and runtime behavior.

## 7. Verification Matrix

| Area | Verification |
| --- | --- |
| Config parsing | Unit tests for `capture_logs` default, explicit enablement, and `log_dir` |
| Relative path resolution | Unit test resolves relative `log_dir` against the current run directory |
| Build ID handling | Unit test or focused integration test for `ResponseEvent::Build` path setup |
| Early/missing build event | Tests for buffered early stream events and warning-only fallback when build ID never arrives |
| Log writes | Unit test verifies `stdout.log` and `stderr.log` contents |
| Suppression message | Unit test verifies path-based notice when capture is active |
| Final notice | Unit test verifies both saved log paths are printed at build completion |
| Fallback path | Unit test verifies warning plus legacy hint when log capture fails, including invalid build IDs and mid-stream write failure |
| Integration | Focused `read_responses` test using mock NDJSON input and real temp files |
| Formatting / lint / build | `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release` |
| Docs | Manual review of README and requirements changes |

## 8. Milestone Commit Gate

Do not create an implementation commit until all of the following are true:

- H0 decisions are locked.
- Two independent planning reviews have been completed or fallback has been documented.
- Every review finding is triaged as `accept`, `defer`, or `reject`.
- Design and phase plan status fields are updated to `Locked`.

## 9. Operator Checklist and Evidence Log Schema

### 9.1 Checklist

1. Confirm the feature folder exists and contains the required planning artifacts.
2. Run two independent review passes using `agent-runner-review`.
3. Record reviewer run IDs directly from the live session stream.
4. Triage every finding.
5. Apply accepted documentation changes.
6. Lock the status fields.
7. Publish a handoff contract for execution.

### 9.2 Evidence Log Schema

For each phase, append an entry with:

- Completion date:
- Commit hash(es):
- Acceptance evidence:
- Review run IDs + triage outcomes:
- Go / No-Go decision:

### 9.3 Planning Review Evidence

- Gemini run ID: `r_20260308030834981_898c49b0`
- PI run ID: `r_20260308030904938_2c623d12`
- Findings triage:
  - `accept`: specify relative `log_dir` semantics and lock it in H0
  - `accept`: specify late-bound log-path handling in `OutputLimiter`
  - `accept`: define early-stream buffering and missing-build-event fallback
  - `accept`: define buffered-writer plus flush-per-event policy
  - `accept`: define single-warning fallback for mid-stream write failures
  - `accept`: add final saved-log-path completion notice
  - `accept`: add focused integration coverage for `read_responses`
  - `accept`: add tests for early/missing build event and fallback messaging
  - `accept`: document temp-dir retention characteristics in user-facing docs
  - `reject`: add stress testing as a planning gate in v1; rationale: deterministic unit and focused integration coverage are sufficient for the first implementation pass
- Notes:
  - Reviews completed from live session streams and incorporated before locking docs.
  - H0 exit remains blocked until implementation execution begins from these locked artifacts.

### 9.4 Execution Phase Evidence

#### Phase H0: Contract Lock

- Completion date: 2026-03-07
- Commit hash(es): `b842566`
- Acceptance evidence:
  - Locked docs updated to clarify that the final saved-log notice is emitted on `stderr`, invalid build IDs disable capture with a warning, and log-capture fallback is triggered by the first directory creation or file write failure.
  - Verification passed before commit: `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release`.
- Review run IDs + triage outcomes:
  - Gemini `r_20260308033519033_6aa9a948`
    - `accept`: lock the completion notice to `stderr`.
    - `reject`: add bounded early-stream buffering in v1; rationale: the locked v1 contract assumes the server emits the `build` event first, and adding a new buffer cap would expand scope beyond H0.
  - PI `r_20260308033519055_35376925`
    - `accept`: clarify safe handling for build IDs used as path components.
    - `accept`: add explicit verification for relative `log_dir` resolution.
    - `reject`: add new concurrency handling for duplicate build IDs; rationale: the existing UUID-based server contract makes collisions non-normative for v1.
    - `reject`: add extra conversion-lifecycle wording for `String` to `PathBuf` and writer close semantics; rationale: the locked design already fixes path-resolution timing and flush-per-event behavior sufficiently for implementation.
- Go / No-Go decision: Go

#### Phase H1: Config and Log Sink Plumbing

- Completion date: 2026-03-07
- Commit hash(es): `f03d862`
- Acceptance evidence:
  - `src/bin/build-cli.rs` now parses `output.capture_logs` and `output.log_dir`, resolves relative `log_dir` values against the process start directory, and defaults capture storage to `temp_dir()/build-service` when capture is enabled without an explicit directory.
  - `read_responses()` now consumes `ResponseEvent::Build { id, .. }`, validates the build ID as a single path component, initializes `<base>/<build_id>/stdout.log` and `stderr.log`, and stores the late-bound log paths on `OutputLimiter` for H2 messaging.
  - Verification passed before commit: `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release`.
- Review run IDs + triage outcomes:
  - Gemini `r_20260308034250353_8bd4ebaa`
    - `reject`: downgrade empty `output.log_dir` to warning-and-fallback; rationale: malformed config remains a startup validation error, while the locked fallback semantics apply after capture is enabled at runtime.
    - `reject`: avoid creating zero-byte log files in H1; rationale: H1 explicitly initializes the per-build sink and directory layout, and H2 will populate the already-open writers.
    - `defer`: add dedicated config/log-sink tests in H1; rationale: the locked phase plan reserves the test expansion for H3.
  - PI `r_20260308034250353_f746672c`
    - `accept`: rename placeholder sink writer fields for clearer intent.
    - `accept`: reject NUL bytes in `build_id` during client-side path validation.
    - `reject`: canonicalize resolved relative `log_dir` paths; rationale: the locked contract requires resolution against the startup run directory, not path normalization.
    - `defer`: add dedicated H1 unit coverage for path resolution and sink initialization in H3, per the locked phase ordering.
- Go / No-Go decision: Go

#### Phase H2: Streaming Integration and User Messaging

- Completion date: 2026-03-07
- Commit hash(es): `b53fd2c`
- Acceptance evidence:
  - `read_responses()` now buffers pre-build `stdout`/`stderr` events while capture is requested, drains buffered events in original order after the `build` event initializes the sink, and flushes buffered events back to the terminal with a single warning if capture cannot be initialized.
  - `BuildLogSink` now writes complete `stdout` and `stderr` stream payloads to `<base>/<build_id>/stdout.log` and `stderr.log`, flushing after every event, while `LineLimiter` continues to enforce terminal max-line and tail-line behavior separately.
  - Suppression notices now point to the saved per-stream log path when capture is healthy, fall back to the existing env-var hint when capture is unavailable, and `read_responses()` emits a final `stderr` completion notice with both log paths when capture remains active through completion.
  - Verification passed before commit: `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release`.
- Review run IDs + triage outcomes:
  - Gemini `r_20260308034817227_e9102a60`
    - `reject`: add a bounded pre-build buffer in v1; rationale: H0 already locked this as an accepted residual risk outside the v1 scope.
    - `defer`: add H2 runtime coverage for buffering, fallback, and completion notices in H3, per the locked phase ordering.
  - PI `r_20260308034817242_b7e721d7`
    - `accept`: remove stale `#[allow(dead_code)]` annotations from actively used sink writers.
    - `reject`: revisit flush-per-event performance in H2; rationale: the locked design explicitly chose per-event flushes for crash-safety and live log usefulness.
    - `defer`: add focused H2 tests for path-based suppression, buffering, fallback, and final notices in H3.
    - `defer`: document temp-dir accumulation behavior in README and requirements during H3 documentation updates.
- Go / No-Go decision: Go

#### Phase H3: Tests and Documentation

- Completion date: 2026-03-07
- Commit hash(es): `e2fa8e0`
- Acceptance evidence:
  - Added unit coverage in `src/bin/build-cli.rs` for capture-enabled config resolution, absolute/relative/empty `log_dir` handling, build-id validation, path-based suppression messaging, write-failure fallback, and a focused `read_responses()` integration with mock NDJSON and real temp files.
  - Added CLI integration coverage in `tests/build_cli_log_capture.rs` for relative `log_dir` resolution from the startup run directory, saved-log completion notices with and without suppression, disabled-capture regression behavior, missing build-event fallback, and invalid build-ID fallback.
  - Updated `README.md` and `requirements.md` with the new `[output]` keys, saved-log layout, relative-path semantics, fallback behavior, terminal-only limit semantics, and temp-dir retention caveat.
  - Updated `CHANGELOG.md` under `## [Unreleased]` with the new feature summary. The PR link remains pending because no PR number exists in this local execution context.
  - `docs/reference/architecture.md` and `docs/implementation/implementation-plan.md` are not present in this repository, so there were no corresponding finalization files to update.
  - Verification passed before commit: `cargo fmt`, `cargo clippy`, `cargo test`, `cargo build --release`.
- Review run IDs + triage outcomes:
  - Gemini `r_20260308035620592_d20bb25b`
    - `reject`: no additional changes required; reviewer reported H3 complete against the locked design and phase plan.
  - PI `r_20260308035620603_d03eda81`
    - `accept`: add an integration test proving the final saved-log notice appears even when no suppression occurs.
    - `accept`: add explicit coverage for disabled capture mode and absolute / empty `log_dir` handling.
    - `reject`: add extra pre-build `stderr` buffering coverage in H3; rationale: the current buffering path is symmetric across stream variants and the phase gate is already satisfied by existing unit and integration coverage.
    - `reject`: block H3 on a PR-numbered changelog link; rationale: the changelog entry is present, and the repo-specific PR-link completion step must happen when a PR number actually exists.
- Go / No-Go decision: Go

## 10. Handoff Contract

Use `$agent-runner-spec-execution` and `$agent-runner-review`.

Topic slug: `build-cli-log-capture`.

Read order:
1. `docs/implementation/build-cli-log-capture/design.md`
2. `docs/implementation/build-cli-log-capture/phase-task-plan.md`

Execution start point:
1. Start at H0 only.

Boundaries and semantic-preservation constraints:

- No protocol or server changes.
- Keep the existing output-limit env vars functional.
- Keep feature behavior additive and config-gated.
- Do not rename the chosen config keys without updating the locked docs first.

Review policy requirements:

- Follow the repo review policy plus the phase-plan Section 9 evidence requirements.

Completion requirements:

- Update README and `requirements.md` when behavior lands.
- Update Section 9 evidence with implementation-phase results.
- Provide a final phase summary with verification results and residual risks.
