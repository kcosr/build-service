use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "3";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub timeout_sec: Option<u64>,
    #[serde(default)]
    pub artifacts: ArtifactSpec,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub workspace: Option<WorkspaceRequest>,
}

impl Request {
    pub fn schema_version_or_default(&self) -> &str {
        self.schema_version.as_deref().unwrap_or(SCHEMA_VERSION)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactSpec {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactArchive {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceRequest {
    #[serde(default)]
    pub reuse: bool,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub create: Option<bool>,
    #[serde(default)]
    pub refresh: Option<bool>,
    #[serde(default)]
    pub ttl_sec: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ResponseEvent {
    Build {
        id: String,
        status: String,
    },
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    Error {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pattern: Option<String>,
    },
    Exit {
        code: i32,
        timed_out: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        artifacts: Option<ArtifactArchive>,
        #[serde(skip_serializing_if = "Option::is_none")]
        workspace_id: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_defaults() {
        let request = Request {
            schema_version: None,
            request_id: None,
            command: "make".to_string(),
            args: Vec::new(),
            cwd: None,
            timeout_sec: None,
            artifacts: ArtifactSpec::default(),
            env: None,
            workspace: None,
        };
        assert_eq!(request.schema_version_or_default(), "3");
    }

    #[test]
    fn response_event_serialization() {
        let event = ResponseEvent::Stdout {
            data: "hello".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert_eq!(json, "{\"type\":\"stdout\",\"data\":\"hello\"}");

        let parsed: ResponseEvent = serde_json::from_str(&json).expect("deserialize");
        match parsed {
            ResponseEvent::Stdout { data } => assert_eq!(data, "hello"),
            _ => panic!("unexpected variant"),
        }
    }
}
