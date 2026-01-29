# Feature/Improvement Design: Workspace Branch Macro

## Overview

Support a `{branch}` macro in the workspace `id` field of the local TOML configuration file (`.build-service/config.toml`). This allows dynamic workspace paths based on the current git branch, enabling per-branch workspace isolation without manual configuration changes.

## Motivation

- **Per-branch isolation**: Different branches may have incompatible build artifacts (e.g., different dependencies, generated files). Using a branch-specific workspace prevents cross-contamination.
- **Worktree support**: Users working with git worktrees need separate workspaces per worktree/branch automatically.
- **Reduced manual config**: Eliminates the need to manually update `workspace.id` when switching branches.

## Proposed Solution

Split responsibilities between client and server:

- **Client (build-cli)**: Macro expansion - replace `{branch}` with actual git branch name
- **Server (build-service)**: Sanitization - ensure workspace IDs are safe for filesystem use

### Configuration Example

```toml
[workspace]
reuse = true
id = "myproject-{branch}"
create = true
ttl_sec = 0
```

When on branch `feature/add-auth`, the client expands to `myproject-feature/add-auth`, then the server sanitizes to `myproject-feature-add-auth`.

### Implementation Approach

**Client-side (macro expansion):**
1. Check if `workspace.id` contains `{branch}`
2. Run `git rev-parse --abbrev-ref HEAD` to get current branch
3. Replace `{branch}` with the raw branch name (no sanitization)
4. Send expanded ID to server

**Server-side (sanitization):**
1. Receive workspace ID from client
2. Sanitize to match `[A-Za-z0-9_-]+` requirements
3. Use sanitized ID for filesystem operations

### Sanitization Rules (Server-side)

Apply these transformations to incoming workspace IDs:
- Replace `/` with `-` (common in `feature/xyz` branches and template paths)
- Replace other invalid characters with `-`
- Collapse multiple consecutive `-` into a single `-`
- Trim leading/trailing `-`
- Truncate if resulting ID exceeds reasonable length (e.g., 128 chars)

Examples:
- `vsl-main` → `vsl-main` (no change)
- `vsl-feature/auth` → `vsl-feature-auth`
- `VSL/main` → `VSL-main`
- `my//project-test` → `my-project-test`

## Files to Update

| File | Changes |
|------|---------|
| `src/bin/build-cli.rs` | Add `expand_workspace_macros()` function in `resolve_workspace_config()` |
| `src/bin/build-cli.rs` | Add `get_git_branch()` helper function |
| `src/bin/build-cli.rs` | Remove `is_valid_workspace_id()` validation (server will sanitize) |
| `src/workspace.rs` | Add `sanitize_workspace_id()` function |
| `src/workspace.rs` | Update `plan_request()` to sanitize incoming workspace IDs instead of rejecting |

## Implementation Steps

### Client-side (build-cli.rs)

1. **Add `get_git_branch()` function**
   - Execute `git rev-parse --abbrev-ref HEAD`
   - Return `Result<String, io::Error>`
   - Handle detached HEAD by returning "detached"

2. **Add `expand_workspace_macros()` function**
   - Take workspace ID string as input
   - If contains `{branch}`, resolve and substitute with raw branch name
   - Return expanded string or error if git command fails

3. **Update `resolve_workspace_config()`**
   - After reading `id` from config/env, call `expand_workspace_macros()`
   - Remove the `is_valid_workspace_id()` check (server handles it)

### Server-side (workspace.rs)

4. **Add `sanitize_workspace_id()` function**
   - Replace `/` and other invalid chars with `-`
   - Collapse consecutive `-`
   - Trim leading/trailing `-`
   - Truncate to max length
   - Return sanitized ID

5. **Update `plan_request()`**
   - Instead of returning `WorkspaceError::InvalidId`, call `sanitize_workspace_id()`
   - Use sanitized ID in the `WorkspacePlan`

6. **Add tests**
   - Client: Test macro expansion with various branch names
   - Client: Test error handling when not in git repo
   - Server: Test sanitization of various IDs with special chars

## Resolved Questions

1. **Additional macros?** → Only `{branch}` for now. Additional macros can be added later if needed.
2. **Detached HEAD behavior** → Use literal string `detached` as the branch name.
3. **Env var override** → Yes, `BUILD_SERVICE_WORKSPACE_ID` env var will also support macros.
4. **Template with special chars** → Server sanitizes the entire ID. `VSL/{branch}` is valid.
5. **Where does sanitization happen?** → Server-side, so all clients benefit and behavior is consistent.

## Alternatives Considered

### Alternative 1: Client-side sanitization (rejected)
The client could sanitize before sending. However, server-side sanitization ensures consistency across all clients and provides a single source of truth for valid workspace IDs.

### Alternative 2: Server-side macro expansion (rejected)
The server could expand macros, but this would require sending git context to the server and complicates the protocol. Macro expansion stays client-side since only the client has git access.

### Alternative 3: Template syntax (`${branch}`)
Could use `${branch}` instead of `{branch}`. The `{...}` syntax is simpler and sufficient since we only have a few macros.

### Alternative 4: Shell command execution (rejected)
Allow arbitrary shell commands like `$(git branch --show-current)`. This is more flexible but introduces security concerns and complexity. Explicit macros are safer.

## Out of Scope

- Server-side macro expansion
- Custom user-defined macros
- Macro support in other config fields (sources, artifacts, etc.)
