use std::fs;
use std::process::Command;

use tempfile::TempDir;

fn run_build_cli(local_fallback: bool) -> std::process::Output {
    let temp = TempDir::new().expect("temp dir");
    let repo_root = temp.path();
    let config_dir = repo_root.join(".build-service");
    fs::create_dir_all(&config_dir).expect("create config dir");
    fs::write(repo_root.join("hello.txt"), "hello").expect("write source");

    let config = format!(
        r#"[sources]
include = ["hello.txt"]

[artifacts]
include = ["out/**"]

[connection]
local_fallback = {local_fallback}
"#
    );
    fs::write(config_dir.join("config.toml"), config).expect("write config");

    let socket_path = repo_root.join("missing.sock");
    assert!(!socket_path.exists(), "socket should not exist");
    let endpoint = format!("unix://{}", socket_path.display());

    Command::new(env!("CARGO_BIN_EXE_build-cli"))
        .current_dir(repo_root)
        .arg("--endpoint")
        .arg(&endpoint)
        .arg("make")
        .output()
        .expect("run build-cli")
}

#[test]
fn build_cli_returns_fallback_code_when_local_fallback_enabled() {
    let output = run_build_cli(true);

    assert_eq!(output.status.code(), Some(222));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("build request failed"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn build_cli_returns_error_code_when_local_fallback_disabled() {
    let output = run_build_cli(false);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("build request failed"),
        "unexpected stderr: {stderr}"
    );
}
