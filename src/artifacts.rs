use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use glob::glob;
use tracing::{info, warn};
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::ZipWriter;

use crate::config::ArtifactsConfig;
use crate::protocol::{ArtifactArchive, ArtifactSpec};
use crate::validation::validate_relative_pattern;

const DEFAULT_GC_INTERVAL_SECS: u64 = 3600;

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
}

pub fn collect_artifacts_zip(
    build_root: &Path,
    spec: &ArtifactSpec,
    config: &ArtifactsConfig,
    build_id: &str,
) -> Result<Option<ArtifactArchive>, ArtifactError> {
    if spec.include.is_empty() {
        return Ok(None);
    }

    let root = fs::canonicalize(build_root).map_err(|source| ArtifactError::Io {
        context: "canonicalize build_root",
        source,
    })?;

    let exclude_patterns = compile_patterns(&spec.exclude)?;
    let mut matched_files: HashMap<PathBuf, PathBuf> = HashMap::new();

    for pattern in &spec.include {
        validate_relative_pattern(pattern, "artifacts.include").map_err(|err| {
            ArtifactError::InvalidPattern {
                message: err.to_string(),
            }
        })?;

        let pattern_root = root.join(pattern).to_string_lossy().into_owned();
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
            return Err(ArtifactError::GlobMiss {
                pattern: pattern.to_string(),
            });
        }
    }

    let dest_dir = config.storage_root.join(build_id);
    fs::create_dir_all(&dest_dir).map_err(|source| ArtifactError::Io {
        context: "create artifact directory",
        source,
    })?;

    let dest = dest_dir.join("artifacts.zip");
    write_artifacts_zip(&dest, &matched_files)?;

    let size = fs::metadata(&dest).map_err(|source| ArtifactError::Io {
        context: "stat artifacts.zip",
        source,
    })?;

    Ok(Some(ArtifactArchive {
        path: format!("/v1/builds/{build_id}/artifacts.zip"),
        size: size.len(),
    }))
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

fn compile_patterns(patterns: &[String]) -> Result<Vec<glob::Pattern>, ArtifactError> {
    let mut compiled = Vec::new();
    for pattern in patterns {
        validate_relative_pattern(pattern, "artifacts.exclude").map_err(|err| {
            ArtifactError::InvalidPattern {
                message: err.to_string(),
            }
        })?;
        let glob = glob::Pattern::new(pattern).map_err(|source| ArtifactError::GlobPattern {
            pattern: pattern.to_string(),
            source,
        })?;
        compiled.push(glob);
    }
    Ok(compiled)
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
) -> Result<(), ArtifactError> {
    let file = File::create(dest).map_err(|source| ArtifactError::Io {
        context: "create artifacts.zip",
        source,
    })?;
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    let mut items: Vec<_> = matched_files.iter().collect();
    items.sort_by(|a, b| a.1.cmp(b.1));

    for (source, rel) in items {
        let name = rel.to_string_lossy().replace('\\', "/");
        zip.start_file(name, options)
            .map_err(|source| ArtifactError::Zip { source })?;
        let mut input = File::open(source).map_err(|source| ArtifactError::Io {
            context: "open artifact",
            source,
        })?;
        io::copy(&mut input, &mut zip).map_err(|source| ArtifactError::Io {
            context: "write artifact",
            source,
        })?;
    }

    zip.finish()
        .map_err(|source| ArtifactError::Zip { source })?;
    Ok(())
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

    #[test]
    fn collect_artifacts_glob_miss() {
        let root = tempdir().expect("tempdir");
        let config = ArtifactsConfig {
            storage_root: root.path().join("artifacts"),
            ttl_sec: None,
            gc_interval_sec: None,
            max_bytes: None,
        };
        let spec = ArtifactSpec {
            include: vec!["out/*.bin".to_string()],
            exclude: vec![],
        };

        let err = collect_artifacts_zip(root.path(), &spec, &config, "bld").unwrap_err();
        match err {
            ArtifactError::GlobMiss { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn collect_artifacts_creates_zip() {
        let root = tempdir().expect("tempdir");
        let config = ArtifactsConfig {
            storage_root: root.path().join("artifacts"),
            ttl_sec: None,
            gc_interval_sec: None,
            max_bytes: None,
        };
        let output = root.path().join("out");
        std::fs::create_dir_all(&output).expect("mkdir");
        std::fs::write(output.join("app"), "bin").expect("write");
        let spec = ArtifactSpec {
            include: vec!["out/**".to_string()],
            exclude: vec![],
        };

        let archive = collect_artifacts_zip(root.path(), &spec, &config, "bld")
            .expect("collect")
            .expect("archive");
        assert!(archive.path.ends_with("artifacts.zip"));
        let zip_path = config.storage_root.join("bld").join("artifacts.zip");
        assert!(zip_path.exists());
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

        let config = ArtifactsConfig {
            storage_root: root.path().join("artifacts"),
            ttl_sec: None,
            gc_interval_sec: None,
            max_bytes: None,
        };
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
}
