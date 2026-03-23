use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use tempfile::TempDir;

fn write_executable(path: &std::path::Path, body: &str) {
    fs::write(path, body).expect("write executable");
    let mut perms = fs::metadata(path).expect("stat executable").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod executable");
}

fn setup_wrapper_env() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let temp = TempDir::new().expect("temp dir");
    let wrapper_bin = temp.path().join("wrapper-bin");
    let local_bin = temp.path().join("local-bin");
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::create_dir_all(&wrapper_bin).expect("create wrapper bin");
    fs::create_dir_all(&local_bin).expect("create local bin");

    symlink(
        manifest_dir.join("scripts/build-wrapper.sh"),
        wrapper_bin.join("make"),
    )
    .expect("symlink wrapper");
    write_executable(
        &wrapper_bin.join("build-cli"),
        "#!/bin/sh\nprintf 'build-cli:%s\\n' \"$*\"\n",
    );
    write_executable(
        &local_bin.join("make"),
        "#!/bin/sh\nprintf 'local:%s\\n' \"$*\"\n",
    );

    (temp, wrapper_bin, local_bin)
}

#[test]
fn wrapper_uses_build_cli_when_endpoint_env_is_set_without_repo_config() {
    let (temp, wrapper_bin, local_bin) = setup_wrapper_env();
    let system_path = std::env::var("PATH").expect("PATH");
    let output = Command::new(wrapper_bin.join("make"))
        .current_dir(temp.path())
        .env(
            "PATH",
            format!(
                "{}:{}:{}",
                wrapper_bin.display(),
                local_bin.display(),
                system_path
            ),
        )
        .env("BUILD_SERVICE_ENDPOINT", "unix:///tmp/build-service.sock")
        .output()
        .expect("run wrapper");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("build-cli:make"),
        "unexpected stdout: {stdout}"
    );
    assert!(!stdout.contains("local:"), "unexpected stdout: {stdout}");
}

#[test]
fn wrapper_falls_back_to_local_tool_without_config_or_endpoint() {
    let (temp, wrapper_bin, local_bin) = setup_wrapper_env();
    let system_path = std::env::var("PATH").expect("PATH");
    let output = Command::new(wrapper_bin.join("make"))
        .current_dir(temp.path())
        .env(
            "PATH",
            format!(
                "{}:{}:{}",
                wrapper_bin.display(),
                local_bin.display(),
                system_path
            ),
        )
        .output()
        .expect("run wrapper");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("local:"), "unexpected stdout: {stdout}");
    assert!(
        !stdout.contains("build-cli:"),
        "unexpected stdout: {stdout}"
    );
}
