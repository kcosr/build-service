use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    pub project_id: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub timeout_sec: Option<u64>,
    #[serde(rename = "ref", default)]
    pub ref_override: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,
}

impl Request {
    pub fn schema_version_or_default(&self) -> &str {
        self.schema_version.as_deref().unwrap_or(SCHEMA_VERSION)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub name: String,
    pub url: String,
    pub content_type: String,
    pub size: u64,
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
    Warning {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pattern: Option<String>,
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
        artifacts: Option<Vec<ArtifactInfo>>,
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
            project_id: "project".to_string(),
            command: "make".to_string(),
            args: Vec::new(),
            cwd: None,
            timeout_sec: None,
            ref_override: None,
            auth_token: None,
        };
        assert_eq!(request.schema_version_or_default(), "2");
    }

    #[test]
    fn schema_version_pass_through() {
        let request = Request {
            schema_version: Some("2".to_string()),
            request_id: None,
            project_id: "project".to_string(),
            command: "make".to_string(),
            args: Vec::new(),
            cwd: None,
            timeout_sec: None,
            ref_override: None,
            auth_token: None,
        };
        assert_eq!(request.schema_version_or_default(), "2");
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

    #[test]
    fn response_event_exit_serialization() {
        let event = ResponseEvent::Exit {
            code: 5,
            timed_out: true,
            artifacts: None,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert_eq!(json, "{\"type\":\"exit\",\"code\":5,\"timed_out\":true}");
    }

    #[test]
    fn response_event_build_serialization() {
        let event = ResponseEvent::Build {
            id: "bld_123".to_string(),
            status: "started".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert_eq!(
            json,
            "{\"type\":\"build\",\"id\":\"bld_123\",\"status\":\"started\"}"
        );
    }
}
