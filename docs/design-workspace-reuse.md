# Workspace Reuse (Concise Design)

## Goal
Reuse build workspaces across runs to enable incremental builds while keeping the default behavior unchanged.

## Key Decisions
- **IDs:** `ws_<uuid>` for server-generated workspace directories, `bld_<uuid>` for build runs/artifacts.
- **Source handling:** Always extract sources into the workspace. Reuse does not clean old files. A manifest lets the server skip rewriting unchanged files; `refresh` forces a full resync.
- **Workspace metadata:** Only for reusable workspaces; stored inside `.build-service/` in the workspace (metadata + manifest).
- **Ephemeral builds:** No metadata written; workspace deleted after build.
- **Client control:** Reuse is enabled via client config/env; no CLI flags.
- **TTL:** Server has a **default TTL**; client may override per request. No max TTL.
- **Permanent workspaces:** `ttl_sec = 0` if server allows it.
- **Client-supplied IDs:** Supported with an explicit `create` flag and must match `^[A-Za-z0-9_-]+$` (no required prefix). No tenancy; any client can reuse any ID.

## Storage Layout
```
<data_root>/workspaces/
├── <workspace_id>/
│   ├── .build-service/meta.json
│   └── .build-service/manifest.json
└── <workspace_id>/
    ├── .build-service/meta.json
    └── .build-service/manifest.json

<artifacts_root>/bld_<uuid>/artifacts.zip
```

## Metadata (persistent workspaces only)
Path: `<workspace_dir>/.build-service/meta.json`
```json
{
  "workspace_id": "<workspace_id>",
  "ttl_sec": 7200,
  "last_used": "2026-01-20T06:20:12Z"
}
```

Path: `<workspace_dir>/.build-service/manifest.json`
```json
{
  "version": 1,
  "entries": {"src/lib.rs": {"size": 123, "hash": "<blake3>"}}
}
```

Server must ignore `.build-service/**` from the source zip and exclude it from artifacts.

## Request/Response
### Request
```json
{
  "workspace": {
    "reuse": true,
    "id": "custom_id",        // optional
    "create": true,           // optional, only used with id
    "refresh": false,         // optional
    "ttl_sec": 3600           // optional, 0 = permanent
  },
  "command": "make",
  "args": ["-j4"]
}
```

### Response (NDJSON)
```
{"type":"build","id":"bld_<uuid>","status":"started"}
{"type":"exit","code":0,"workspace_id":"<workspace_id>","artifacts":{"path":"/v1/builds/bld_<uuid>/artifacts.zip","size":123}}
```
Note: For ephemeral builds, omit `workspace_id` in the exit event.

## Server Behavior
### Ephemeral build (no workspace block)
1. Generate `ws_<uuid>` and `bld_<uuid>`.
2. Create `<data_root>/workspaces/ws_<uuid>`.
3. Extract sources (always).
4. Run build in workspace.
5. Collect artifacts under `bld_<uuid>`.
6. **Delete workspace dir.** No metadata or manifest.

### Reuse enabled, no workspace id
1. Generate `ws_<uuid>` and `bld_<uuid>`.
2. Create workspace dir + `.build-service/`.
3. Extract sources (always). Use `manifest.json` to skip rewriting unchanged files unless `refresh` is set.
4. Run build; collect artifacts.
5. Write/update `meta.json` with TTL/last_used; write `manifest.json`.
6. **Keep workspace dir.**

### Reuse enabled, id provided
- If workspace exists: reuse it, extract sources, update metadata.
- If missing:
  - `create=true` → create new workspace with provided id.
  - `create=false` or absent → **reject request**.

### Concurrency (workspace lock)
- A workspace may only have **one active build** at a time.
- Server tracks an `active` flag in memory for each `workspace_id`.
- If a build request arrives for a workspace with `active=true`, reject with `409 workspace_busy`.
- `active` is set when build starts and cleared in a `finally`/drop guard on completion or error.
- On server startup, all workspaces default to `active=false` (no running builds).
- This design assumes a **single server instance**.

## TTL Rules (server)
- If client provides `ttl_sec`: use exactly that value.
- If not provided: use server `default_ttl_sec`.
- `ttl_sec = 0` → permanent (only if `allow_permanent = true`).

## Client Behavior
### Config
```toml
[workspace]
reuse = true
id = "custom_id"        # optional
create = true           # optional
refresh = false         # optional

# optional default
# ttl_sec = 3600
```

### Env overrides
```
BUILD_SERVICE_WORKSPACE_REUSE=true
BUILD_SERVICE_WORKSPACE_ID=custom_id
BUILD_SERVICE_WORKSPACE_CREATE=true
BUILD_SERVICE_WORKSPACE_REFRESH=true
BUILD_SERVICE_WORKSPACE_TTL=3600
```

### Workspace id file
- `.build-service/workspace-id`
- Only read when reuse is enabled.
- Stored from exit event when server returns `workspace_id`.

## Open Items
- None.

## Persistence Across Restarts
- Workspace state is persisted via `<workspace_dir>/.build-service/meta.json`.
- On startup, the server scans `<data_root>/workspaces/*` and loads any `meta.json` it finds.
- GC and reuse checks rely on this metadata, so workspaces survive restarts.
