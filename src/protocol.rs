use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: String,
    #[serde(default)]
    pub timeout_sec: Option<u64>,
}

impl Request {
    pub fn schema_version_or_default(&self) -> &str {
        self.schema_version.as_deref().unwrap_or(SCHEMA_VERSION)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ResponseEvent {
    Stdout { data: String },
    Stderr { data: String },
    Exit { code: i32, timed_out: bool },
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
            cwd: "/tmp".to_string(),
            timeout_sec: None,
        };
        assert_eq!(request.schema_version_or_default(), "1");
    }

    #[test]
    fn schema_version_pass_through() {
        let request = Request {
            schema_version: Some("2".to_string()),
            request_id: None,
            command: "make".to_string(),
            args: Vec::new(),
            cwd: "/tmp".to_string(),
            timeout_sec: None,
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
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert_eq!(json, "{\"type\":\"exit\",\"code\":5,\"timed_out\":true}");
    }
}
