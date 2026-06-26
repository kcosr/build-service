use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use glob::glob;
use tracing::{info, warn};
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::ZipWriter;

use crate::config::ArtifactsConfig;
use crate::protocol::{ArtifactArchive, ArtifactRestrictions, ArtifactSpec};
use crate::validation::validate_relative_pattern;

const DEFAULT_GC_INTERVAL_SECS: u64 = 3600;
const INTERNAL_EXCLUDE_PATTERN: &str = ".build-service/**";
const TRANSFER_LIMIT_SENTINEL: &str = "artifacts.max_transfer_bytes exceeded";

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact pattern {pattern} matched nothing")]
    GlobMiss { pattern: String },

    #[error("invalid artifact glob pattern {pattern}: {source}")]
    GlobPattern {
        pattern: String,
        #[source]
        source: glob::PatternError,
    },

    #[error("artifact path {path:?} is outside build root")]
    OutsideRoot { path: PathBuf },

    #[error("artifact io error ({context}): {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("failed to zip artifacts: {source}")]
    Zip {
        #[source]
        source: zip::result::ZipError,
    },

    #[error("invalid artifact pattern: {message}")]
    InvalidPattern { message: String },

    #[error("artifact archive exceeds artifacts.max_transfer_bytes ({max_bytes} bytes)")]
    TransferTooLarge { max_bytes: u64 },

    #[error("artifact contents exceed artifacts.max_uncompressed_bytes ({max_bytes} bytes)")]
    UncompressedTooLarge { max_bytes: u64 },
}

#[derive(Debug, Clone)]
pub struct ArtifactCollection {
    pub archive: Option<ArtifactArchive>,
    pub restrictions: Option<ArtifactRestrictions>,
}

pub fn collect_artifacts_zip(
    build_root: &Path,
    spec: &ArtifactSpec,
    config: &ArtifactsConfig,
    build_id: &str,
) -> Result<ArtifactCollection, ArtifactError> {
    if spec.include.is_empty() {
        return Ok(ArtifactCollection {
            archive: None,
            restrictions: None,
        });
    }

    let root = fs::canonicalize(build_root).map_err(|source| ArtifactError::Io {
        context: "canonicalize build_root",
        source,
    })?;

    let mut excludes = spec.exclude.clone();
    excludes.push(INTERNAL_EXCLUDE_PATTERN.to_string());
    let exclude_patterns = compile_patterns(&excludes, "artifacts.exclude")?;
    let mut matched_files: HashMap<PathBuf, PathBuf> = HashMap::new();

    for pattern in &spec.include {
        validate_relative_pattern(pattern, "artifacts.include").map_err(|err| {
            ArtifactError::InvalidPattern {
                message: err.to_string(),
            }
        })?;

        let pattern_root = root.join(pattern).to_string_lossy().into_owned();
        info!(
            "artifact glob: pattern={:?} root={:?} full_path={:?}",
            pattern, root, pattern_root
        );
        let entries = glob(&pattern_root).map_err(|source| ArtifactError::GlobPattern {
            pattern: pattern.to_string(),
            source,
        })?;

        let mut found = false;
        if collect_recursive_prefix(pattern, &root, &exclude_patterns, &mut matched_files)? {
            found = true;
        }

        for entry in entries {
            let path = entry.map_err(|source| ArtifactError::Io {
                context: "expand artifact glob",
                source: io::Error::other(source.to_string()),
            })?;
            info!("artifact glob matched: {:?}", path);
            found = true;
            let canonical = fs::canonicalize(&path).map_err(|source| ArtifactError::Io {
                context: "canonicalize artifact path",
                source,
            })?;

            if !canonical.starts_with(&root) {
                return Err(ArtifactError::OutsideRoot { path: canonical });
            }

            if canonical.is_dir() {
                collect_dir_files(&canonical, &root, &exclude_patterns, &mut matched_files)?;
            } else if canonical.is_file() {
                let rel = canonical
                    .strip_prefix(&root)
                    .map_err(|_| ArtifactError::OutsideRoot {
                        path: canonical.clone(),
                    })?
                    .to_path_buf();
                if !is_excluded(&rel, &exclude_patterns) {
                    matched_files.entry(canonical).or_insert(rel);
                }
            }
        }

        if !found {
            info!(
                "artifact pattern matched nothing, skipping: pattern={:?} checked_path={:?}",
                pattern, pattern_root
            );
        }
    }

    let restrictions = apply_restricted_patterns(
        &mut matched_files,
        &config.restricted_patterns,
        "artifacts.restricted_patterns",
    )?;

    // If no files matched any patterns, return None
    if matched_files.is_empty() {
        info!("no artifacts matched any patterns");
        return Ok(ArtifactCollection {
            archive: None,
            restrictions,
        });
    }

    let dest_dir = config.storage_root.join(build_id);
    fs::create_dir_all(&dest_dir).map_err(|source| ArtifactError::Io {
        context: "create artifact directory",
        source,
    })?;

    let total_uncompressed_bytes = sum_matched_file_sizes(&matched_files)?;
    if let Some(max_uncompressed_bytes) = config.max_uncompressed_bytes {
        if total_uncompressed_bytes > max_uncompressed_bytes {
            return Err(ArtifactError::UncompressedTooLarge {
                max_bytes: max_uncompressed_bytes,
            });
        }
    }

    let dest = dest_dir.join("artifacts.zip");
    let size = write_artifacts_zip(
        &dest,
        &matched_files,
        config.max_transfer_bytes,
        config.max_uncompressed_bytes,
    )?;

    Ok(ArtifactCollection {
        archive: Some(ArtifactArchive {
            path: format!("/v1/builds/{build_id}/artifacts.zip"),
            size,
        }),
        restrictions,
    })
}

fn sum_matched_file_sizes(matched_files: &HashMap<PathBuf, PathBuf>) -> Result<u64, ArtifactError> {
    let mut total = 0u64;
    for source in matched_files.keys() {
        let metadata = fs::metadata(source).map_err(|source| ArtifactError::Io {
            context: "stat artifact for size",
            source,
        })?;
        total = total.saturating_add(metadata.len());
    }
    Ok(total)
}

fn collect_recursive_prefix(
    pattern: &str,
    root: &Path,
    exclude_patterns: &[glob::Pattern],
    matched_files: &mut HashMap<PathBuf, PathBuf>,
) -> Result<bool, ArtifactError> {
    let base = if pattern == "**" {
        Some("")
    } else {
        pattern
            .strip_suffix("/**")
            .or_else(|| pattern.strip_suffix("\\**"))
    };

    let Some(base) = base else {
        return Ok(false);
    };

    let base_path = if base.is_empty() {
        root.to_path_buf()
    } else {
        root.join(base)
    };

    if !base_path.exists() {
        return Ok(false);
    }

    let canonical = fs::canonicalize(&base_path).map_err(|source| ArtifactError::Io {
        context: "canonicalize artifact prefix",
        source,
    })?;

    if !canonical.starts_with(root) {
        return Err(ArtifactError::OutsideRoot { path: canonical });
    }

    if canonical.is_dir() {
        collect_dir_files(&canonical, root, exclude_patterns, matched_files)?;
        return Ok(true);
    }

    Ok(false)
}

fn compile_patterns(patterns: &[String], field: &str) -> Result<Vec<glob::Pattern>, ArtifactError> {
    let mut compiled = Vec::new();
    for pattern in patterns {
        validate_relative_pattern(pattern, field).map_err(|err| ArtifactError::InvalidPattern {
            message: err.to_string(),
        })?;
        let glob = glob::Pattern::new(pattern).map_err(|source| ArtifactError::GlobPattern {
            pattern: pattern.to_string(),
            source,
        })?;
        compiled.push(glob);
    }
    Ok(compiled)
}

fn apply_restricted_patterns(
    matched_files: &mut HashMap<PathBuf, PathBuf>,
    restricted_patterns: &[String],
    field: &str,
) -> Result<Option<ArtifactRestrictions>, ArtifactError> {
    if restricted_patterns.is_empty() || matched_files.is_empty() {
        return Ok(None);
    }

    let compiled = compile_patterns(restricted_patterns, field)?;
    let mut restricted_paths = HashSet::new();
    let mut matched_pattern_indexes = HashSet::new();

    for (canonical, rel) in matched_files.iter() {
        let rel_str = rel.to_string_lossy();
        let mut restricted = false;
        for (index, pattern) in compiled.iter().enumerate() {
            if pattern.matches(&rel_str) {
                restricted = true;
                matched_pattern_indexes.insert(index);
            }
        }
        if restricted {
            restricted_paths.insert(canonical.clone());
        }
    }

    if restricted_paths.is_empty() {
        return Ok(None);
    }

    let omitted_count = restricted_paths.len();
    for path in restricted_paths {
        matched_files.remove(&path);
    }

    let matched_patterns = restricted_patterns
        .iter()
        .enumerate()
        .filter(|(index, _pattern)| matched_pattern_indexes.contains(index))
        .map(|(_index, pattern)| pattern.clone())
        .collect();

    Ok(Some(ArtifactRestrictions {
        omitted_count,
        matched_patterns,
    }))
}

fn collect_dir_files(
    dir: &Path,
    root: &Path,
    exclude_patterns: &[glob::Pattern],
    matched_files: &mut HashMap<PathBuf, PathBuf>,
) -> Result<(), ArtifactError> {
    for entry in WalkDir::new(dir) {
        let entry = entry.map_err(|source| ArtifactError::Io {
            context: "walk artifact dir",
            source: io::Error::other(source.to_string()),
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let canonical = fs::canonicalize(entry.path()).map_err(|source| ArtifactError::Io {
            context: "canonicalize artifact file",
            source,
        })?;
        if !canonical.starts_with(root) {
            return Err(ArtifactError::OutsideRoot { path: canonical });
        }
        let rel = canonical
            .strip_prefix(root)
            .map_err(|_| ArtifactError::OutsideRoot {
                path: canonical.clone(),
            })?
            .to_path_buf();
        if is_excluded(&rel, exclude_patterns) {
            continue;
        }
        matched_files.entry(canonical).or_insert(rel);
    }
    Ok(())
}

fn is_excluded(path: &Path, patterns: &[glob::Pattern]) -> bool {
    if patterns.is_empty() {
        return false;
    }

    let path_str = path.to_string_lossy();
    patterns.iter().any(|pattern| pattern.matches(&path_str))
}

fn write_artifacts_zip(
    dest: &Path,
    matched_files: &HashMap<PathBuf, PathBuf>,
    max_transfer_bytes: Option<u64>,
    max_uncompressed_bytes: Option<u64>,
) -> Result<u64, ArtifactError> {
    use std::os::unix::fs::PermissionsExt;

    let result = (|| {
        let file = File::create(dest).map_err(|source| ArtifactError::Io {
            context: "create artifacts.zip",
            source,
        })?;
        let transfer_limit = Rc::new(Cell::new(max_transfer_bytes));
        let mut zip = ZipWriter::new(LimitedWriter::new(file, Rc::clone(&transfer_limit)));

        let mut items: Vec<_> = matched_files.iter().collect();
        items.sort_by(|a, b| a.1.cmp(b.1));

        let mut uncompressed_bytes = 0u64;
        let mut buffer = [0u8; 8192];

        for (source, rel) in items {
            let name = rel.to_string_lossy().replace('\\', "/");

            // Preserve source permissions inside the archive.
            let metadata = fs::metadata(source).map_err(|source| ArtifactError::Io {
                context: "stat artifact for permissions",
                source,
            })?;
            let mode = metadata.permissions().mode();

            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(mode);

            if let Err(source) = zip.start_file(name, options) {
                if is_transfer_limit_zip_error(&source) {
                    finish_after_transfer_limit(&mut zip, &transfer_limit);
                    return Err(ArtifactError::TransferTooLarge {
                        max_bytes: max_transfer_bytes.expect("transfer limit must be set"),
                    });
                }
                return Err(ArtifactError::Zip { source });
            }

            let mut input = File::open(source).map_err(|source| ArtifactError::Io {
                context: "open artifact",
                source,
            })?;

            loop {
                let bytes = input
                    .read(&mut buffer)
                    .map_err(|source| ArtifactError::Io {
                        context: "read artifact",
                        source,
                    })?;
                if bytes == 0 {
                    break;
                }

                uncompressed_bytes = uncompressed_bytes.saturating_add(bytes as u64);
                if let Some(limit) = max_uncompressed_bytes {
                    if uncompressed_bytes > limit {
                        return Err(ArtifactError::UncompressedTooLarge { max_bytes: limit });
                    }
                }

                if let Err(source) = zip.write_all(&buffer[..bytes]) {
                    if is_transfer_limit_error(&source) {
                        finish_after_transfer_limit(&mut zip, &transfer_limit);
                        return Err(ArtifactError::TransferTooLarge {
                            max_bytes: max_transfer_bytes.expect("transfer limit must be set"),
                        });
                    }
                    return Err(ArtifactError::Io {
                        context: "write artifact",
                        source,
                    });
                }
            }
        }

        let writer = match zip.finish() {
            Ok(writer) => writer,
            Err(source) => {
                if is_transfer_limit_zip_error(&source) {
                    finish_after_transfer_limit(&mut zip, &transfer_limit);
                    return Err(ArtifactError::TransferTooLarge {
                        max_bytes: max_transfer_bytes.expect("transfer limit must be set"),
                    });
                }
                return Err(ArtifactError::Zip { source });
            }
        };
        Ok(writer.bytes_written())
    })();

    if result.is_err() {
        let _ = fs::remove_file(dest);
    }

    result
}

fn finish_after_transfer_limit<W: io::Write + io::Seek>(
    zip: &mut ZipWriter<LimitedWriter<W>>,
    transfer_limit: &Rc<Cell<Option<u64>>>,
) {
    transfer_limit.set(None);
    let _ = zip.finish();
}

fn is_transfer_limit_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Other && err.to_string() == TRANSFER_LIMIT_SENTINEL
}

fn is_transfer_limit_zip_error(err: &zip::result::ZipError) -> bool {
    matches!(err, zip::result::ZipError::Io(source) if is_transfer_limit_error(source))
}

struct LimitedWriter<W> {
    inner: W,
    bytes_written: u64,
    max_bytes: Rc<Cell<Option<u64>>>,
}

impl<W> LimitedWriter<W> {
    fn new(inner: W, max_bytes: Rc<Cell<Option<u64>>>) -> Self {
        Self {
            inner,
            bytes_written: 0,
            max_bytes,
        }
    }

    fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

impl<W: io::Write> io::Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(max_bytes) = self.max_bytes.get() {
            if self.bytes_written.saturating_add(buf.len() as u64) > max_bytes {
                return Err(io::Error::other(TRANSFER_LIMIT_SENTINEL));
            }
        }

        let written = self.inner.write(buf)?;
        self.bytes_written = self.bytes_written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: io::Seek> io::Seek for LimitedWriter<W> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

pub fn spawn_gc_task(config: crate::config::Config) {
    if config.artifacts.ttl_sec.is_none() && config.artifacts.max_bytes.is_none() {
        return;
    }

    let artifacts = config.artifacts.clone();
    let interval = artifacts
        .gc_interval_sec
        .unwrap_or(DEFAULT_GC_INTERVAL_SECS);

    std::thread::spawn(move || loop {
        if let Err(err) = gc_artifacts(&artifacts) {
            warn!("artifact gc failed: {err}");
        }
        std::thread::sleep(Duration::from_secs(interval));
    });
}

fn gc_artifacts(config: &ArtifactsConfig) -> Result<(), ArtifactError> {
    let mut entries = scan_artifact_entries(&config.storage_root)?;
    if entries.is_empty() {
        return Ok(());
    }

    if let Some(ttl_sec) = config.ttl_sec {
        let cutoff = SystemTime::now()
            .checked_sub(Duration::from_secs(ttl_sec))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        entries.retain(|entry| {
            if entry.modified < cutoff {
                if let Err(err) = fs::remove_dir_all(&entry.path) {
                    warn!("failed to remove expired artifacts {:?}: {err}", entry.path);
                    return true;
                }
                info!("removed expired artifacts {:?}", entry.path);
                return false;
            }
            true
        });
    }

    if let Some(max_bytes) = config.max_bytes {
        let mut total: u64 = entries.iter().map(|entry| entry.size).sum();
        if total > max_bytes {
            entries.sort_by_key(|entry| entry.modified);
            for entry in entries {
                if total <= max_bytes {
                    break;
                }
                if let Err(err) = fs::remove_dir_all(&entry.path) {
                    warn!("failed to remove artifacts {:?}: {err}", entry.path);
                    continue;
                }
                info!("removed artifacts {:?} to enforce max_bytes", entry.path);
                total = total.saturating_sub(entry.size);
            }
        }
    }

    Ok(())
}

struct ArtifactEntry {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

fn scan_artifact_entries(root: &Path) -> Result<Vec<ArtifactEntry>, ArtifactError> {
    let mut entries = Vec::new();
    let read_dir = match fs::read_dir(root) {
        Ok(read_dir) => read_dir,
        Err(err) => {
            if err.kind() == io::ErrorKind::NotFound {
                return Ok(entries);
            }
            return Err(ArtifactError::Io {
                context: "read artifacts root",
                source: err,
            });
        }
    };

    for entry in read_dir {
        let entry = entry.map_err(|source| ArtifactError::Io {
            context: "read artifacts entry",
            source,
        })?;
        let path = entry.path();
        let meta = entry.metadata().map_err(|source| ArtifactError::Io {
            context: "stat artifacts entry",
            source,
        })?;
        if !meta.is_dir() {
            continue;
        }

        let (size, modified) = scan_entry(&path)?;
        entries.push(ArtifactEntry {
            path,
            size,
            modified,
        });
    }

    Ok(entries)
}

fn scan_entry(path: &Path) -> Result<(u64, SystemTime), ArtifactError> {
    let mut total = 0u64;
    let mut newest = SystemTime::UNIX_EPOCH;

    for entry in WalkDir::new(path) {
        let entry = entry.map_err(|source| ArtifactError::Io {
            context: "walk artifacts",
            source: io::Error::other(source.to_string()),
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let meta = entry.metadata().map_err(|source| ArtifactError::Io {
            context: "stat artifacts",
            source: io::Error::other(source.to_string()),
        })?;
        total = total.saturating_add(meta.len());
        if let Ok(modified) = meta.modified() {
            if modified > newest {
                newest = modified;
            }
        }
    }

    Ok((total, newest))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;
    use zip::ZipArchive;

    fn artifacts_config(root: &Path) -> ArtifactsConfig {
        ArtifactsConfig {
            storage_root: root.join("artifacts"),
            ..ArtifactsConfig::default()
        }
    }

    fn zip_entry_names(path: &Path) -> Vec<String> {
        let file = File::open(path).expect("open zip");
        let mut archive = ZipArchive::new(file).expect("read zip");
        let mut names = Vec::new();
        for index in 0..archive.len() {
            names.push(
                archive
                    .by_index(index)
                    .expect("zip entry")
                    .name()
                    .to_string(),
            );
        }
        names
    }

    #[test]
    fn collect_artifacts_no_match_returns_none() {
        let root = tempdir().expect("tempdir");
        let config = artifacts_config(root.path());
        let spec = ArtifactSpec {
            include: vec!["out/*.bin".to_string()],
            exclude: vec![],
        };

        // Glob miss no longer fails - just returns None if no files matched
        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").unwrap();
        assert!(
            result.archive.is_none(),
            "expected None when no files match"
        );
        assert!(result.restrictions.is_none());
    }

    #[test]
    fn collect_artifacts_creates_zip() {
        let root = tempdir().expect("tempdir");
        let config = artifacts_config(root.path());
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app"), "bin").expect("write");
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };

        let archive = collect_artifacts_zip(root.path(), &spec, &config, "bld")
            .expect("collect")
            .archive
            .expect("archive");
        assert!(archive.path.ends_with("artifacts.zip"));
        let zip_path = config.storage_root.join("bld").join("artifacts.zip");
        assert!(zip_path.exists());
    }

    #[test]
    fn collect_artifacts_omits_restricted_files_and_reports_patterns() {
        let root = tempdir().expect("tempdir");
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app.bin"), "bin").expect("write app");
        std::fs::write(root.path().join("foo.cpp"), "source").expect("write source");

        let mut config = artifacts_config(root.path());
        config.restricted_patterns = vec!["foo.*".to_string(), "*.cpp".to_string()];
        let spec = ArtifactSpec {
            include: vec!["**".to_string(), "foo.cpp".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        let restrictions = result.restrictions.expect("restrictions");
        assert_eq!(restrictions.omitted_count, 1);
        assert_eq!(restrictions.matched_patterns, vec!["foo.*", "*.cpp"]);

        let archive = result.archive.expect("archive");
        assert!(archive.path.ends_with("artifacts.zip"));
        let names = zip_entry_names(&config.storage_root.join("bld").join("artifacts.zip"));
        assert_eq!(names, vec!["out/app.bin"]);
    }

    #[test]
    fn collect_artifacts_all_restricted_returns_no_archive_with_summary() {
        let root = tempdir().expect("tempdir");
        std::fs::write(root.path().join("foo.cpp"), "source").expect("write source");

        let mut config = artifacts_config(root.path());
        config.restricted_patterns = vec!["*.cpp".to_string()];
        let spec = ArtifactSpec {
            include: vec!["*.cpp".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        assert!(result.archive.is_none());
        let restrictions = result.restrictions.expect("restrictions");
        assert_eq!(restrictions.omitted_count, 1);
        assert_eq!(restrictions.matched_patterns, vec!["*.cpp"]);
        assert!(!config
            .storage_root
            .join("bld")
            .join("artifacts.zip")
            .exists());
    }

    #[test]
    fn collect_artifacts_absent_restriction_match_returns_no_summary() {
        let root = tempdir().expect("tempdir");
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app.bin"), "bin").expect("write app");

        let mut config = artifacts_config(root.path());
        config.restricted_patterns = vec!["*.cpp".to_string()];
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        assert!(result.archive.is_some());
        assert!(result.restrictions.is_none());
    }

    #[test]
    fn collect_artifacts_restricted_files_do_not_count_toward_size_limits() {
        let root = tempdir().expect("tempdir");
        std::fs::write(root.path().join("large.h"), "artifact payload").expect("write source");

        let mut config = artifacts_config(root.path());
        config.max_uncompressed_bytes = Some(1);
        config.restricted_patterns = vec!["*.h".to_string()];
        let spec = ArtifactSpec {
            include: vec!["*.h".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        assert!(result.archive.is_none());
        let restrictions = result.restrictions.expect("restrictions");
        assert_eq!(restrictions.omitted_count, 1);
        assert_eq!(restrictions.matched_patterns, vec!["*.h"]);
    }

    #[test]
    fn collect_artifacts_internal_excludes_are_not_reported_as_restrictions() {
        let root = tempdir().expect("tempdir");
        let internal = root.path().join(".build-service");
        let output = root.path().join("out");
        std::fs::create_dir_all(&internal).expect("mkdir internal");
        std::fs::create_dir_all(&output).expect("mkdir out");
        std::fs::write(internal.join("generated.h"), "internal").expect("write internal");
        std::fs::write(output.join("app.bin"), "bin").expect("write app");

        let mut config = artifacts_config(root.path());
        config.restricted_patterns = vec!["**/*.h".to_string()];
        let spec = ArtifactSpec {
            include: vec!["**".to_string()],
            exclude: vec![],
        };

        let result = collect_artifacts_zip(root.path(), &spec, &config, "bld").expect("collect");
        assert!(result.archive.is_some());
        assert!(result.restrictions.is_none());
        let names = zip_entry_names(&config.storage_root.join("bld").join("artifacts.zip"));
        assert_eq!(names, vec!["out/app.bin"]);
    }

    #[cfg(unix)]
    #[test]
    fn collect_artifacts_rejects_symlink_outside_root() {
        let root = tempdir().expect("tempdir");
        let outside = tempdir().expect("tempdir");
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret").expect("write");

        let link_path = root.path().join("link.txt");
        symlink(&outside_file, &link_path).expect("symlink");

        let config = artifacts_config(root.path());
        let spec = ArtifactSpec {
            include: vec!["link.txt".to_string()],
            exclude: vec![],
        };

        let err = collect_artifacts_zip(root.path(), &spec, &config, "bld").unwrap_err();
        match err {
            ArtifactError::OutsideRoot { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn collect_artifacts_enforces_max_uncompressed_bytes() {
        let root = tempdir().expect("tempdir");
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app.txt"), "artifact payload").expect("write");
        let config = ArtifactsConfig {
            storage_root: root.path().join("artifacts"),
            max_uncompressed_bytes: Some(8),
            ..ArtifactsConfig::default()
        };
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };

        let err = collect_artifacts_zip(root.path(), &spec, &config, "bld").unwrap_err();
        assert!(matches!(
            err,
            ArtifactError::UncompressedTooLarge { max_bytes: 8 }
        ));
        assert!(
            !config
                .storage_root
                .join("bld")
                .join("artifacts.zip")
                .exists(),
            "oversized archives should be removed"
        );
    }

    #[test]
    fn collect_artifacts_enforces_max_transfer_bytes() {
        let root = tempdir().expect("tempdir");
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app.txt"), "artifact payload").expect("write");
        let config = ArtifactsConfig {
            storage_root: root.path().join("artifacts"),
            max_transfer_bytes: Some(1),
            ..ArtifactsConfig::default()
        };
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };

        let err = collect_artifacts_zip(root.path(), &spec, &config, "bld").unwrap_err();
        assert!(matches!(
            err,
            ArtifactError::TransferTooLarge { max_bytes: 1 }
        ));
        assert!(
            !config
                .storage_root
                .join("bld")
                .join("artifacts.zip")
                .exists(),
            "oversized archives should be removed"
        );
    }
}
