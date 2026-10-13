use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

use build_service::artifacts::{collect_artifacts_zip, ArtifactCollection};
use build_service::config::ArtifactsConfig;
use build_service::protocol::ArtifactSpec;
use tempfile::TempDir;
use tracing::Level;
use zip::ZipArchive;

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct TestWorkspace {
    temp: TempDir,
    config: ArtifactsConfig,
}

impl TestWorkspace {
    fn new(files: &[&str]) -> Self {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join("workspace")).unwrap();
        for file in files {
            let path = temp.path().join("workspace").join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "artifact contents").unwrap();
        }
        let config = ArtifactsConfig {
            storage_root: temp.path().join("artifacts"),
            ..ArtifactsConfig::default()
        };
        Self { temp, config }
    }

    fn collect(
        &self,
        spec: &ArtifactSpec,
        build_id: &str,
        level: Level,
    ) -> (ArtifactCollection, String) {
        let logs = LogBuffer::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_max_level(level)
            .with_writer(move || writer.clone())
            .finish();
        let collection = tracing::subscriber::with_default(subscriber, || {
            collect_artifacts_zip(
                &self.temp.path().join("workspace"),
                spec,
                &self.config,
                build_id,
            )
            .unwrap()
        });
        let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        (collection, text)
    }

    fn archive_names(&self, build_id: &str) -> Vec<String> {
        let file = fs::File::open(
            self.config
                .storage_root
                .join(build_id)
                .join("artifacts.zip"),
        )
        .unwrap();
        let mut zip = ZipArchive::new(file).unwrap();
        (0..zip.len())
            .map(|index| zip.by_index(index).unwrap().name().to_owned())
            .collect()
    }
}

fn spec(include: &[&str], exclude: &[&str]) -> ArtifactSpec {
    ArtifactSpec {
        include: include
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect(),
        exclude: exclude
            .iter()
            .map(|pattern| (*pattern).to_owned())
            .collect(),
    }
}

fn exclusions(logs: &str) -> Vec<&str> {
    logs.lines()
        .filter(|line| line.contains("artifact excluded"))
        .collect()
}

fn exclusion_for<'a>(logs: &'a str, build_id: &str, path: &str, source: &str) -> &'a str {
    let path_field = format!("path={:?}", Path::new(path));
    let matches: Vec<_> = exclusions(logs)
        .into_iter()
        .filter(|line| line.contains(&path_field))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected one decision for {path:?}: {logs}"
    );
    let line = matches[0];
    assert!(line.contains("INFO"), "{line}");
    assert!(line.contains("artifact_collection"), "{line}");
    assert!(
        line.contains("build_id=") && line.contains(build_id),
        "{line}"
    );
    assert!(line.contains(&format!("source={source:?}")), "{line}");
    line
}

#[test]
fn client_and_internal_exclusions_are_logged_once_across_overlapping_includes() {
    let workspace = TestWorkspace::new(&[
        "out/drop.tmp",
        "out/nested/deep.tmp",
        "out/keep.bin",
        ".build-service/state.json",
    ]);
    let request = spec(
        &["**", "out/**", "out/drop.tmp", ".build-service/**"],
        &["out/drop.tmp", "**/*.tmp"],
    );
    let (collection, logs) = workspace.collect(&request, "bld_client", Level::INFO);
    assert!(collection.archive.is_some());
    assert!(collection.restrictions.is_none());
    assert_eq!(workspace.archive_names("bld_client"), ["out/keep.bin"]);
    assert_eq!(exclusions(&logs).len(), 3, "{logs}");
    let direct = exclusion_for(&logs, "bld_client", "out/drop.tmp", "client");
    assert!(direct.contains("pattern=\"out/drop.tmp\""), "{direct}");
    let nested = exclusion_for(&logs, "bld_client", "out/nested/deep.tmp", "client");
    assert!(nested.contains("pattern=\"**/*.tmp\""), "{nested}");
    let internal = exclusion_for(&logs, "bld_client", ".build-service/state.json", "internal");
    assert!(
        internal.contains("pattern=\".build-service/**\""),
        "{internal}"
    );
    assert!(logs.contains("artifact glob matched"), "{logs}");
    for line in exclusions(&logs) {
        assert!(!line.contains("out/keep.bin"), "{line}");
        assert!(
            !line.contains(workspace.temp.path().to_str().unwrap()),
            "{line}"
        );
    }
}

#[test]
fn client_rules_keep_their_provenance_when_equal_to_the_internal_rule() {
    let workspace = TestWorkspace::new(&[".build-service/state.json"]);
    let request = spec(&[".build-service/**"], &[".build-service/**"]);
    let (collection, logs) = workspace.collect(&request, "bld_provenance", Level::INFO);
    assert!(collection.archive.is_none());
    assert!(collection.restrictions.is_none());
    assert_eq!(exclusions(&logs).len(), 1, "{logs}");
    let decision = exclusion_for(
        &logs,
        "bld_provenance",
        ".build-service/state.json",
        "client",
    );
    assert!(
        decision.contains("pattern=\".build-service/**\""),
        "{decision}"
    );
}

#[test]
fn server_restriction_logs_include_all_matches_without_adding_paths_to_the_response() {
    let mut workspace = TestWorkspace::new(&[
        "out/secret.cc",
        "out/nested/other.cc",
        "out/client.cc",
        "out/app.bin",
    ]);
    workspace.config.restricted_patterns = vec!["**/*.cc".to_owned(), "out/secret.*".to_owned()];
    let request = spec(
        &["out/**", "out/secret.cc", "out/nested/**"],
        &["out/client.cc"],
    );
    let (collection, logs) = workspace.collect(&request, "bld_server", Level::INFO);
    assert!(collection.archive.is_some());
    assert_eq!(workspace.archive_names("bld_server"), ["out/app.bin"]);
    let restrictions = collection.restrictions.unwrap();
    assert_eq!(restrictions.omitted_count, 2);
    assert_eq!(restrictions.matched_patterns, ["**/*.cc", "out/secret.*"]);
    assert_eq!(
        serde_json::to_value(restrictions).unwrap(),
        serde_json::json!({"omitted_count": 2, "matched_patterns": ["**/*.cc", "out/secret.*"]})
    );
    assert_eq!(exclusions(&logs).len(), 3, "{logs}");
    let secret = exclusion_for(&logs, "bld_server", "out/secret.cc", "server");
    assert!(
        secret.contains("patterns=[\"**/*.cc\", \"out/secret.*\"]"),
        "{secret}"
    );
    let nested = exclusion_for(&logs, "bld_server", "out/nested/other.cc", "server");
    assert!(nested.contains("patterns=[\"**/*.cc\"]"), "{nested}");
    exclusion_for(&logs, "bld_server", "out/client.cc", "client");
    for line in exclusions(&logs) {
        assert!(!line.contains("out/app.bin"), "{line}");
        assert!(
            !line.contains(workspace.temp.path().to_str().unwrap()),
            "{line}"
        );
    }
}

#[test]
fn all_excluded_collections_log_decisions_even_without_an_archive() {
    for source in ["client", "server"] {
        let mut workspace = TestWorkspace::new(&["out/denied.cc"]);
        let request = if source == "client" {
            spec(&["out/**", "out/denied.cc"], &["**/*.cc"])
        } else {
            workspace.config.restricted_patterns = vec!["**/*.cc".to_owned()];
            spec(&["out/**", "out/denied.cc"], &[])
        };
        let (collection, logs) = workspace.collect(&request, "bld_empty", Level::INFO);
        assert!(collection.archive.is_none());
        assert_eq!(collection.restrictions.is_some(), source == "server");
        assert!(!workspace.config.storage_root.join("bld_empty").exists());
        assert_eq!(exclusions(&logs).len(), 1, "{logs}");
        exclusion_for(&logs, "bld_empty", "out/denied.cc", source);
    }
}

#[test]
fn exclusions_respect_the_info_level_filter() {
    let workspace = TestWorkspace::new(&["out/denied.cc"]);
    let request = spec(&["out/**"], &["**/*.cc"]);
    let (collection, logs) = workspace.collect(&request, "bld_info", Level::INFO);
    assert!(collection.archive.is_none());
    exclusion_for(&logs, "bld_info", "out/denied.cc", "client");
    let (collection, logs) = workspace.collect(&request, "bld_warn", Level::WARN);
    assert!(collection.archive.is_none());
    assert!(logs.is_empty(), "{logs}");
}

#[cfg(unix)]
#[test]
fn exclusion_paths_escape_newlines_in_filenames() {
    let path = "out/line\nbreak.cc";
    let workspace = TestWorkspace::new(&[path]);
    let (collection, logs) =
        workspace.collect(&spec(&["out/**"], &["**/*.cc"]), "bld_escape", Level::INFO);
    assert!(collection.archive.is_none());
    assert_eq!(exclusions(&logs).len(), 1, "{logs}");
    exclusion_for(&logs, "bld_escape", path, "client");
    assert!(!logs.contains("line\nbreak.cc"), "{logs}");
}
