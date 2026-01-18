# Workspace Reuse Design

## Overview

Currently each build creates a fresh workspace directory, extracts sources, builds, and deletes the workspace. This means every build starts from scratch.

This feature would allow reusing workspace directories across builds to enable incremental builds.

## Flow

### First build from a checkout

1. Client checks `.build-service/workspace-id` - doesn't exist
2. Client packages sources, sends request without `workspace_id`
3. Server creates `ws_<uuid>` workspace, extracts sources
4. Server runs build, collects artifacts
5. Server returns `workspace_id` in response
6. Client saves workspace_id to `.build-service/workspace-id`

### Subsequent builds from same checkout

1. Client reads `.build-service/workspace-id` → e.g., `ws_abc123`
2. Client packages sources, sends request with `workspace_id=ws_abc123`
3. Server checks if workspace exists and not expired:
   - **Yes**: Sync sources (delete removed files, extract zip over existing)
   - **No**: Create new workspace, extract fresh
4. Server runs build, collects artifacts
5. Server returns `workspace_id` (same or new if recreated)
6. Client updates `.build-service/workspace-id` if changed

## Source Sync Strategy

- Server tracks file list from last extraction in a separate metadata directory (not in workspace, to avoid it being pulled back as an artifact)
- On new build with existing workspace:
  1. Compare file list from new zip to stored list
  2. Delete files that are no longer in the zip
  3. Extract new zip (overwrites existing, adds new)
- No hashes needed - the zip is the source of truth

## Protocol Changes

### Request

New optional field:

```json
{
  "workspace_id": "ws_abc123",
  "command": "make",
  ...
}
```

### Exit Event

New field in exit event:

```json
{
  "type": "exit",
  "code": 0,
  "workspace_id": "ws_abc123",
  "artifacts": { ... }
}
```

## Configuration

### Server config

```toml
[build]
# TTL for workspace reuse. 0 = no reuse (current behavior)
workspace_ttl_sec = 28800  # 8 hours default
```

### Client file

```
.build-service/workspace-id
```

Contents: just the workspace ID string, e.g., `ws_abc123`

This file should be added to `.gitignore` so each checkout maintains its own workspace identity.

## Storage Layout

```
/var/build-service/
├── workspaces/
│   └── builds/           # Temporary builds (current behavior when no reuse)
│       └── bld_xxx/
├── persistent/           # Reusable workspaces
│   └── ws_abc123/
│       └── <extracted sources and build outputs>
├── workspace-meta/       # Metadata separate from workspaces
│   └── ws_abc123/
│       ├── file-list.txt # List of files from last extraction
│       └── last-used     # Timestamp for TTL
└── artifacts/
    └── bld_xxx/
        └── artifacts.zip
```

## Cleanup

- GC runs periodically (like artifact GC)
- Deletes workspaces where `last-used` timestamp exceeds TTL
- Configurable via `build.workspace_ttl_sec`

## Edge Cases

1. **Workspace deleted by GC mid-session**: Server creates new workspace, returns new ID
2. **Concurrent builds to same workspace**: Need locking or reject with error
3. **Disk space**: May need max workspace count/size limits in addition to TTL

## Not in Scope

- `make clean` does not have special handling - it just runs in the workspace like any other command
- No explicit "delete workspace" command (TTL handles cleanup)
