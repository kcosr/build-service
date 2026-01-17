use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use glob::glob;
use mime_guess::MimeGuess;
use tracing::{info, warn};
use walkdir::WalkDir;
use zip::write::FileOptions;
use zip::ZipWriter;

use crate::config::ArtifactsConfig;
use crate::protocol::ArtifactInfo;

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

    #[error("artifact path {path:?} is outside project root")]
    OutsideRoot { path: PathBuf },

    #[error("artifact io error ({context}): {source}")]
    Io {
        context: &'static str,
        #[source]
        source: io::Error,
    },

    #[error("failed to zip directory {path:?}: {source}")]
    Zip {
        path: PathBuf,
        #[source]
        source: zip::result::ZipError,
    },

    #[error("failed to build artifact url: {message}")]
    Url { message: String },
}

pub fn collect_artifacts(
    project_root: &Path,
    patterns: &[String],
    config: &ArtifactsConfig,
    build_id: &str,
) -> Result<Vec<ArtifactInfo>, ArtifactError> {
    let root = fs::canonicalize(project_root).map_err(|source| ArtifactError::Io {
        context: "canonicalize project_root",
        source,
    })?;

    let mut matches: HashMap<PathBuf, PathBuf> = HashMap::new();

    for pattern in patterns {
        let pattern_root = root.join(pattern).to_string_lossy().into_owned();
        let mut found = Vec::new();

        let entries = glob(&pattern_root).map_err(|source| ArtifactError::GlobPattern {
            pattern: pattern.to_string(),
            source,
        })?;

        for entry in entries {
            let path = entry.map_err(|source| ArtifactError::Io {
                context: "expand artifact glob",
                source: io::Error::other(source.to_string()),
            })?;
            found.push(path);
        }

        if found.is_empty() {
            return Err(ArtifactError::GlobMiss {
                pattern: pattern.to_string(),
            });
        }

        for path in found {
            let canonical = fs::canonicalize(&path).map_err(|source| ArtifactError::Io {
                context: "canonicalize artifact path",
                source,
            })?;

            if !canonical.starts_with(&root) {
                return Err(ArtifactError::OutsideRoot { path: canonical });
            }

            let rel = canonical
                .strip_prefix(&root)
                .map_err(|_| ArtifactError::OutsideRoot {
                    path: canonical.clone(),
                })?
                .to_path_buf();

            matches.entry(canonical).or_insert(rel);
        }
    }

    let mut artifacts = Vec::new();
    let mut items: Vec<(PathBuf, PathBuf)> = matches.into_iter().collect();
    items.sort_by(|a, b| a.1.cmp(&b.1));

    for (source, rel) in items {
        let meta = fs::metadata(&source).map_err(|source| ArtifactError::Io {
            context: "stat artifact",
            source,
        })?;

        if meta.is_dir() {
            let stored_rel = with_zip_extension(&rel);
            let dest = config.storage_root.join(build_id).join(&stored_rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|source| ArtifactError::Io {
                    context: "create artifact parent",
                    source,
                })?;
            }
            zip_directory(&source, &dest)?;
            let size = fs::metadata(&dest).map_err(|source| ArtifactError::Io {
                context: "stat zipped artifact",
                source,
            })?;
            let name = path_to_name(&stored_rel);
            let url = build_artifact_url(&config.public_base_url, build_id, &name)?;

            artifacts.push(ArtifactInfo {
                name,
                url,
                content_type: "application/zip".to_string(),
                size: size.len(),
            });
        } else if meta.is_file() {
            let dest = config.storage_root.join(build_id).join(&rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).map_err(|source| ArtifactError::Io {
                    context: "create artifact parent",
                    source,
                })?;
            }
            fs::copy(&source, &dest).map_err(|source| ArtifactError::Io {
                context: "copy artifact",
                source,
            })?;
            let size = fs::metadata(&dest).map_err(|source| ArtifactError::Io {
                context: "stat artifact",
                source,
            })?;
            let name = path_to_name(&rel);
            let url = build_artifact_url(&config.public_base_url, build_id, &name)?;
            let content_type = MimeGuess::from_path(&rel)
                .first_or_octet_stream()
                .to_string();

            artifacts.push(ArtifactInfo {
                name,
                url,
                content_type,
                size: size.len(),
            });
        }
    }

    Ok(artifacts)
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
                if fs::remove_dir_all(&entry.path).is_ok() {
                    total = total.saturating_sub(entry.size);
                    info!("removed artifacts {:?} to enforce max_bytes", entry.path);
                }
            }
        }
    }

    Ok(())
}

fn scan_artifact_entries(root: &Path) -> Result<Vec<ArtifactEntry>, ArtifactError> {
    let mut entries = Vec::new();
    let dir = match fs::read_dir(root) {
        Ok(dir) => dir,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(entries),
        Err(err) => {
            return Err(ArtifactError::Io {
                context: "read artifacts root",
                source: err,
            })
        }
    };

    for entry in dir {
        let entry = entry.map_err(|source| ArtifactError::Io {
            context: "read artifacts entry",
            source,
        })?;
        let path = entry.path();
        let meta = fs::metadata(&path).map_err(|source| ArtifactError::Io {
            context: "stat artifacts entry",
            source,
        })?;
        if !meta.is_dir() {
            continue;
        }

        let (size, modified) = scan_dir_stats(&path)?;
        entries.push(ArtifactEntry {
            path,
            size,
            modified,
        });
    }

    Ok(entries)
}

fn scan_dir_stats(path: &Path) -> Result<(u64, SystemTime), ArtifactError> {
    let mut size: u64 = 0;
    let mut modified = SystemTime::UNIX_EPOCH;

    for entry in WalkDir::new(path) {
        let entry = entry.map_err(|source| ArtifactError::Io {
            context: "walk artifacts",
            source: io::Error::other(source.to_string()),
        })?;
        let meta = entry.metadata().map_err(|source| ArtifactError::Io {
            context: "stat artifacts",
            source: io::Error::other(source.to_string()),
        })?;
        if meta.is_file() {
            size = size.saturating_add(meta.len());
        }
        if let Ok(mtime) = meta.modified() {
            if mtime > modified {
                modified = mtime;
            }
        }
    }

    Ok((size, modified))
}

fn zip_directory(source: &Path, dest: &Path) -> Result<(), ArtifactError> {
    let file = File::create(dest).map_err(|source| ArtifactError::Io {
        context: "create zip",
        source,
    })?;
    let mut zip = ZipWriter::new(file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for entry in WalkDir::new(source) {
        let entry = entry.map_err(|source| ArtifactError::Io {
            context: "walk zip dir",
            source: io::Error::other(source.to_string()),
        })?;
        let path = entry.path();
        let name = path
            .strip_prefix(source)
            .map_err(|_| ArtifactError::OutsideRoot {
                path: path.to_path_buf(),
            })?;

        if entry.file_type().is_dir() {
            if !name.as_os_str().is_empty() {
                zip.add_directory(name.to_string_lossy(), options)
                    .map_err(|source| ArtifactError::Zip {
                        path: dest.to_path_buf(),
                        source,
                    })?;
            }
            continue;
        }

        zip.start_file(name.to_string_lossy(), options)
            .map_err(|source| ArtifactError::Zip {
                path: dest.to_path_buf(),
                source,
            })?;
        let mut input = File::open(path).map_err(|source| ArtifactError::Io {
            context: "read artifact for zip",
            source,
        })?;
        io::copy(&mut input, &mut zip).map_err(|source| ArtifactError::Io {
            context: "write zip",
            source,
        })?;
    }

    zip.finish().map_err(|source| ArtifactError::Zip {
        path: dest.to_path_buf(),
        source,
    })?;

    Ok(())
}

fn with_zip_extension(path: &Path) -> PathBuf {
    let file_name = match path.file_name() {
        Some(name) => name.to_string_lossy(),
        None => return path.with_extension("zip"),
    };
    path.with_file_name(format!("{file_name}.zip"))
}

fn path_to_name(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn build_artifact_url(base: &str, build_id: &str, name: &str) -> Result<String, ArtifactError> {
    let mut base = base.to_string();
    if !base.ends_with('/') {
        base.push('/');
    }

    let url = url::Url::parse(&base)
        .and_then(|base| base.join(&format!("{build_id}/{name}")))
        .map_err(|err| ArtifactError::Url {
            message: err.to_string(),
        })?;

    Ok(url.to_string())
}

struct ArtifactEntry {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config(root: &Path) -> ArtifactsConfig {
        ArtifactsConfig {
            storage_root: root.join("artifacts"),
            public_base_url: "https://example.com/artifacts".to_string(),
            ttl_sec: None,
            gc_interval_sec: None,
            max_bytes: None,
        }
    }

    #[test]
    fn collect_artifacts_glob_miss() {
        let temp = tempdir().expect("tempdir");
        let project_root = temp.path().join("project");
        std::fs::create_dir_all(&project_root).expect("mkdir");
        let config = test_config(temp.path());

        let err = collect_artifacts(
            &project_root,
            &[String::from("dist/*.tar.gz")],
            &config,
            "bld_test",
        )
        .expect_err("should fail");

        match err {
            ArtifactError::GlobMiss { pattern } => {
                assert_eq!(pattern, "dist/*.tar.gz");
            }
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn collect_artifacts_copies_file() {
        let temp = tempdir().expect("tempdir");
        let project_root = temp.path().join("project");
        let file_path = project_root.join("bin").join("app");
        std::fs::create_dir_all(file_path.parent().unwrap()).expect("mkdir");
        std::fs::write(&file_path, "ok").expect("write");

        let config = test_config(temp.path());
        let artifacts = collect_artifacts(
            &project_root,
            &[String::from("bin/app")],
            &config,
            "bld_test",
        )
        .expect("collect");

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "bin/app");
        let stored = config.storage_root.join("bld_test").join("bin").join("app");
        assert!(stored.exists());
    }

    #[test]
    fn collect_artifacts_zips_directory() {
        let temp = tempdir().expect("tempdir");
        let project_root = temp.path().join("project");
        let dir = project_root.join("out");
        let file_path = dir.join("file.txt");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(&file_path, "ok").expect("write");

        let config = test_config(temp.path());
        let artifacts = collect_artifacts(&project_root, &[String::from("out")], &config, "bld")
            .expect("collect");

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "out.zip");
        let stored = config.storage_root.join("bld").join("out.zip");
        assert!(stored.exists());
    }
}
