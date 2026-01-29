use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::WorkspaceConfig;
use crate::protocol::Request;

const DEFAULT_GC_INTERVAL_SECS: u64 = 3600;
const MAX_WORKSPACE_ID_LEN: usize = 128;

#[derive(Debug, Clone)]
pub struct WorkspacePlan {
    pub id: String,
    pub reuse: bool,
    pub ttl_sec: Option<u64>,
    pub create: bool,
    pub client_supplied: bool,
    pub refresh: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceError {
    #[error("workspace block requires reuse=true")]
    ReuseDisabled,
    #[error("workspace.create requires workspace.id")]
    CreateRequiresId,
    #[error("workspace id must match [A-Za-z0-9_-]+")]
    InvalidId,
    #[error("workspace ttl_sec=0 requires build.workspace.allow_permanent=true")]
    PermanentNotAllowed,
    #[error("workspace is busy")]
    Busy,
    #[error("workspace error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid workspace metadata: {0}")]
    Metadata(String),
}

#[derive(Debug, Clone)]
struct WorkspaceMeta {
    ttl_sec: u64,
    last_used: SystemTime,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkspaceMetaFile {
    workspace_id: String,
    ttl_sec: u64,
    last_used: String,
}

#[derive(Debug)]
pub struct WorkspaceState {
    root: PathBuf,
    settings: WorkspaceConfig,
    active: Mutex<HashSet<String>>,
    metadata: Mutex<HashMap<String, WorkspaceMeta>>,
}

#[derive(Debug)]
pub struct WorkspaceGuard {
    id: String,
    state: Arc<WorkspaceState>,
}

impl Drop for WorkspaceGuard {
    fn drop(&mut self) {
        let mut active = self.state.active.lock().expect("workspace active lock");
        active.remove(&self.id);
    }
}

impl WorkspaceState {
    pub fn new(root: PathBuf, settings: WorkspaceConfig) -> Self {
        let metadata = load_metadata(&root);
        Self {
            root,
            settings,
            active: Mutex::new(HashSet::new()),
            metadata: Mutex::new(metadata),
        }
    }

    pub fn workspace_path(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    pub fn plan_request(&self, request: &Request) -> Result<WorkspacePlan, WorkspaceError> {
        let workspace = request.workspace.as_ref();
        let reuse = workspace.map(|w| w.reuse).unwrap_or(false);

        if !reuse {
            if let Some(workspace) = workspace {
                if workspace.id.is_some()
                    || workspace.create.is_some()
                    || workspace.refresh.is_some()
                    || workspace.ttl_sec.is_some()
                {
                    return Err(WorkspaceError::ReuseDisabled);
                }
            }

            return Ok(WorkspacePlan {
                id: format!("ws_{}", Uuid::new_v4().simple()),
                reuse: false,
                ttl_sec: None,
                create: false,
                client_supplied: false,
                refresh: false,
            });
        }

        let workspace = workspace.expect("workspace must be present when reuse is true");
        if workspace.create == Some(true) && workspace.id.is_none() {
            return Err(WorkspaceError::CreateRequiresId);
        }

        let client_supplied = workspace.id.is_some();
        let id = match &workspace.id {
            Some(id) => {
                let sanitized = sanitize_workspace_id(id);
                if sanitized.is_empty() {
                    return Err(WorkspaceError::InvalidId);
                }
                sanitized
            }
            None => format!("ws_{}", Uuid::new_v4().simple()),
        };

        let create = if client_supplied {
            workspace.create.unwrap_or(false)
        } else {
            true
        };

        let ttl_sec = workspace.ttl_sec.unwrap_or(self.settings.default_ttl_sec);
        if ttl_sec == 0 && !self.settings.allow_permanent {
            return Err(WorkspaceError::PermanentNotAllowed);
        }

        Ok(WorkspacePlan {
            id,
            reuse: true,
            ttl_sec: Some(ttl_sec),
            create,
            client_supplied,
            refresh: workspace.refresh.unwrap_or(false),
        })
    }

    pub fn try_acquire(
        self: &Arc<WorkspaceState>,
        id: &str,
    ) -> Result<WorkspaceGuard, WorkspaceError> {
        let mut active = self.active.lock().expect("workspace active lock");
        if active.contains(id) {
            return Err(WorkspaceError::Busy);
        }
        active.insert(id.to_string());
        Ok(WorkspaceGuard {
            id: id.to_string(),
            state: Arc::clone(self),
        })
    }

    pub fn record_use(&self, plan: &WorkspacePlan) -> Result<(), WorkspaceError> {
        if !plan.reuse {
            return Ok(());
        }
        let ttl_sec = plan.ttl_sec.unwrap_or(self.settings.default_ttl_sec);
        let last_used = SystemTime::now();
        let meta = WorkspaceMeta { ttl_sec, last_used };
        let meta_dir = self.workspace_path(&plan.id).join(".build-service");
        fs::create_dir_all(&meta_dir)?;

        let meta_file = WorkspaceMetaFile {
            workspace_id: plan.id.clone(),
            ttl_sec,
            last_used: format_timestamp(last_used)?,
        };
        let meta_path = meta_dir.join("meta.json");
        let payload = serde_json::to_vec(&meta_file)
            .map_err(|err| WorkspaceError::Metadata(err.to_string()))?;
        fs::write(&meta_path, payload)?;

        let mut metadata = self.metadata.lock().expect("workspace metadata lock");
        metadata.insert(plan.id.clone(), meta);
        Ok(())
    }
}

pub fn spawn_gc_task(state: Arc<WorkspaceState>) {
    let interval = state
        .settings
        .gc_interval_sec
        .unwrap_or(DEFAULT_GC_INTERVAL_SECS);
    std::thread::spawn(move || loop {
        if let Err(err) = gc_workspaces(&state) {
            warn!("workspace gc failed: {err}");
        }
        std::thread::sleep(Duration::from_secs(interval));
    });
}

pub fn is_valid_workspace_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn sanitize_workspace_id(id: &str) -> String {
    let mut output = String::with_capacity(id.len().min(MAX_WORKSPACE_ID_LEN));
    let mut prev_dash = false;

    for ch in id.chars() {
        let normalized = if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            ch
        } else {
            '-'
        };

        if normalized == '-' {
            if output.is_empty() || prev_dash {
                prev_dash = true;
                continue;
            }
            output.push('-');
            prev_dash = true;
        } else {
            output.push(normalized);
            prev_dash = false;
        }

        if output.len() >= MAX_WORKSPACE_ID_LEN {
            break;
        }
    }

    while output.ends_with('-') {
        output.pop();
    }

    output
}

fn gc_workspaces(state: &WorkspaceState) -> Result<(), WorkspaceError> {
    let now = SystemTime::now();
    let expired: Vec<String> = {
        let metadata = state.metadata.lock().expect("workspace metadata lock");
        metadata
            .iter()
            .filter_map(|(id, meta)| {
                if meta.ttl_sec == 0 {
                    return None;
                }
                let cutoff = meta
                    .last_used
                    .checked_add(Duration::from_secs(meta.ttl_sec))?;
                if now > cutoff {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect()
    };

    for id in expired {
        if is_active(state, &id) {
            continue;
        }
        let path = state.workspace_path(&id);
        match fs::remove_dir_all(&path) {
            Ok(_) => {
                info!("removed expired workspace {:?}", path);
                let mut metadata = state.metadata.lock().expect("workspace metadata lock");
                metadata.remove(&id);
            }
            Err(err) => warn!("failed to remove expired workspace {:?}: {err}", path),
        }
    }

    Ok(())
}

fn is_active(state: &WorkspaceState, id: &str) -> bool {
    let active = state.active.lock().expect("workspace active lock");
    active.contains(id)
}

fn load_metadata(root: &Path) -> HashMap<String, WorkspaceMeta> {
    let mut metadata = HashMap::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return metadata,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let dir_name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };

        let meta_path = path.join(".build-service").join("meta.json");
        let bytes = match fs::read(&meta_path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let file: WorkspaceMetaFile = match serde_json::from_slice(&bytes) {
            Ok(file) => file,
            Err(err) => {
                warn!("invalid workspace metadata {:?}: {err}", meta_path);
                continue;
            }
        };
        if file.workspace_id != dir_name {
            warn!(
                "workspace metadata id mismatch: dir={} meta={}",
                dir_name, file.workspace_id
            );
            continue;
        }

        let last_used = match parse_timestamp(&file.last_used) {
            Ok(value) => value,
            Err(err) => {
                warn!("invalid workspace timestamp {:?}: {err}", meta_path);
                continue;
            }
        };

        metadata.insert(
            file.workspace_id.clone(),
            WorkspaceMeta {
                ttl_sec: file.ttl_sec,
                last_used,
            },
        );
    }

    metadata
}

fn format_timestamp(ts: SystemTime) -> Result<String, WorkspaceError> {
    let datetime = OffsetDateTime::from(ts);
    datetime
        .format(&Rfc3339)
        .map_err(|err| WorkspaceError::Metadata(err.to_string()))
}

fn parse_timestamp(value: &str) -> Result<SystemTime, WorkspaceError> {
    let datetime = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|err| WorkspaceError::Metadata(err.to_string()))?;
    let seconds = datetime.unix_timestamp();
    let seconds = if seconds < 0 { 0 } else { seconds as u64 };
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ArtifactSpec, Request, WorkspaceRequest};
    use tempfile::tempdir;

    #[test]
    fn sanitize_workspace_id_replaces_and_collapses() {
        assert_eq!(sanitize_workspace_id("vsl-main"), "vsl-main");
        assert_eq!(
            sanitize_workspace_id("vsl-feature/auth"),
            "vsl-feature-auth"
        );
        assert_eq!(
            sanitize_workspace_id("my//project--test"),
            "my-project-test"
        );
        assert_eq!(sanitize_workspace_id("--bad--id--"), "bad-id");
    }

    #[test]
    fn sanitize_workspace_id_all_invalid_is_empty() {
        assert!(sanitize_workspace_id("!!!").is_empty());
    }

    #[test]
    fn sanitize_workspace_id_truncates() {
        let input = "a".repeat(200);
        let output = sanitize_workspace_id(&input);
        assert_eq!(output.len(), MAX_WORKSPACE_ID_LEN);
    }

    #[test]
    fn plan_request_sanitizes_client_id() {
        let temp = tempdir().expect("tempdir");
        let state = WorkspaceState::new(temp.path().to_path_buf(), WorkspaceConfig::default());
        let request = Request {
            schema_version: None,
            request_id: None,
            command: "make".to_string(),
            args: Vec::new(),
            cwd: None,
            timeout_sec: None,
            artifacts: ArtifactSpec::default(),
            env: None,
            workspace: Some(WorkspaceRequest {
                reuse: true,
                id: Some("feature/add-auth".to_string()),
                create: Some(true),
                refresh: None,
                ttl_sec: None,
            }),
        };

        let plan = state.plan_request(&request).expect("plan");
        assert_eq!(plan.id, "feature-add-auth");
    }
}
