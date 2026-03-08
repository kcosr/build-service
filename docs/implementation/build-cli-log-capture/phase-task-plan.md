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
- Emit a final completion notice with the saved log paths when capture succeeds.
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
| Build ID handling | Unit test or focused integration test for `ResponseEvent::Build` path setup |
| Early/missing build event | Tests for buffered early stream events and warning-only fallback when build ID never arrives |
| Log writes | Unit test verifies `stdout.log` and `stderr.log` contents |
| Suppression message | Unit test verifies path-based notice when capture is active |
| Final notice | Unit test verifies both saved log paths are printed at build completion |
| Fallback path | Unit test verifies warning plus legacy hint when log capture fails, including mid-stream write failure |
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
