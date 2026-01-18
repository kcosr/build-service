use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("cwd must be an absolute path")]
    CwdNotAbsolute,

    #[error("{field} must be a relative path")]
    PathNotRelative { field: String },

    #[error("{field} must not contain parent directory references")]
    PathHasParent { field: String },

    #[error("{field} must not be empty")]
    EmptyValue { field: String },

    #[error("cwd {cwd:?} is outside allowed root {root:?}")]
    CwdOutsideRoot { cwd: PathBuf, root: PathBuf },

    #[error("missing value for {flag}")]
    MissingValue { flag: String },

    #[error("{flag} path {path:?} is outside allowed root {root:?}")]
    PathOutsideRoot {
        flag: String,
        path: PathBuf,
        root: PathBuf,
    },

    #[error("invalid path for {flag}: {source}")]
    InvalidPath {
        flag: String,
        #[source]
        source: std::io::Error,
    },
}

pub fn validate_relative_path(raw: &str, field: &str) -> Result<PathBuf, ValidationError> {
    if raw.trim().is_empty() {
        return Err(ValidationError::EmptyValue {
            field: field.to_string(),
        });
    }

    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(ValidationError::PathNotRelative {
            field: field.to_string(),
        });
    }

    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(ValidationError::PathHasParent {
                field: field.to_string(),
            });
        }
    }

    Ok(path.to_path_buf())
}

pub fn validate_relative_pattern(pattern: &str, field: &str) -> Result<(), ValidationError> {
    if pattern.trim().is_empty() {
        return Err(ValidationError::EmptyValue {
            field: field.to_string(),
        });
    }

    let path = Path::new(pattern);
    if path.is_absolute() {
        return Err(ValidationError::PathNotRelative {
            field: field.to_string(),
        });
    }

    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(ValidationError::PathHasParent {
                field: field.to_string(),
            });
        }
    }

    Ok(())
}

pub fn validate_cwd(cwd: &Path, allowed_root: &Path) -> Result<PathBuf, ValidationError> {
    if !cwd.is_absolute() {
        return Err(ValidationError::CwdNotAbsolute);
    }

    let root =
        std::fs::canonicalize(allowed_root).map_err(|source| ValidationError::InvalidPath {
            flag: "allowed_root".to_string(),
            source,
        })?;
    let canonical_cwd =
        std::fs::canonicalize(cwd).map_err(|source| ValidationError::InvalidPath {
            flag: "cwd".to_string(),
            source,
        })?;

    if !canonical_cwd.starts_with(&root) {
        return Err(ValidationError::CwdOutsideRoot {
            cwd: canonical_cwd,
            root,
        });
    }

    Ok(canonical_cwd)
}

pub fn validate_make_args(
    args: &[String],
    cwd: &Path,
    allowed_root: &Path,
) -> Result<(), ValidationError> {
    let root =
        std::fs::canonicalize(allowed_root).map_err(|source| ValidationError::InvalidPath {
            flag: "allowed_root".to_string(),
            source,
        })?;

    let mut current_dir = cwd.to_path_buf();
    let mut options_done = false;
    let mut iter = args.iter().peekable();

    while let Some(arg) = iter.next() {
        if options_done {
            continue;
        }

        if arg == "--" {
            options_done = true;
            continue;
        }

        if arg == "-C" || arg == "--directory" {
            let value = iter.next().ok_or_else(|| ValidationError::MissingValue {
                flag: arg.to_string(),
            })?;
            current_dir = validate_path(value, &current_dir, &root, arg)?;
            continue;
        }

        if let Some(value) = arg.strip_prefix("-C") {
            if !value.is_empty() {
                current_dir = validate_path(value, &current_dir, &root, "-C")?;
                continue;
            }
        }

        if let Some(value) = arg.strip_prefix("--directory=") {
            current_dir = validate_path(value, &current_dir, &root, "--directory")?;
            continue;
        }

        if arg == "-f" || arg == "--file" {
            let value = iter.next().ok_or_else(|| ValidationError::MissingValue {
                flag: arg.to_string(),
            })?;
            validate_path(value, &current_dir, &root, arg)?;
            continue;
        }

        if let Some(value) = arg.strip_prefix("-f") {
            if !value.is_empty() {
                validate_path(value, &current_dir, &root, "-f")?;
                continue;
            }
        }

        if let Some(value) = arg.strip_prefix("--file=") {
            validate_path(value, &current_dir, &root, "--file")?;
            continue;
        }
    }

    Ok(())
}

fn validate_path(
    raw: &str,
    base: &Path,
    root: &Path,
    flag: &str,
) -> Result<PathBuf, ValidationError> {
    let candidate = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        base.join(raw)
    };

    let canonical =
        std::fs::canonicalize(&candidate).map_err(|source| ValidationError::InvalidPath {
            flag: flag.to_string(),
            source,
        })?;

    if !canonical.starts_with(root) {
        return Err(ValidationError::PathOutsideRoot {
            flag: flag.to_string(),
            path: canonical,
            root: root.to_path_buf(),
        });
    }

    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn validate_cwd_under_root() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("home");
        let workspace = root.join("alice").join("workspace");
        let project = workspace.join("project");
        std::fs::create_dir_all(&project).expect("mkdir");

        let cwd = validate_cwd(&project, &workspace).expect("valid cwd");
        assert!(cwd.starts_with(&workspace));
    }

    #[test]
    fn reject_escape_via_directory_flag() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("home");
        let workspace = root.join("alice").join("workspace");
        let project = workspace.join("project");
        let outside = root.join("alice").join("outside");
        std::fs::create_dir_all(&project).expect("mkdir");
        std::fs::create_dir_all(&outside).expect("mkdir");

        let args = vec!["-C".to_string(), "../../outside".to_string()];
        let err = validate_make_args(&args, &project, &workspace).expect_err("should fail");
        let message = format!("{err}");
        assert!(message.contains("outside"));
    }

    #[test]
    fn validate_multiple_directory_changes() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path().join("home");
        let workspace = root.join("alice").join("workspace");
        let project = workspace.join("project");
        let nested = project.join("subdir");
        std::fs::create_dir_all(&nested).expect("mkdir");
        std::fs::write(nested.join("Makefile"), "all:\n\t@true\n").expect("write");

        let args = vec![
            "-C".to_string(),
            "project".to_string(),
            "-C".to_string(),
            "subdir".to_string(),
            "-f".to_string(),
            "Makefile".to_string(),
        ];

        validate_make_args(&args, &workspace, &workspace).expect("valid args");
    }

    #[test]
    fn validate_relative_path_rejects_absolute() {
        let err = validate_relative_path("/tmp", "cwd").unwrap_err();
        assert!(matches!(err, ValidationError::PathNotRelative { .. }));
    }

    #[test]
    fn validate_relative_path_rejects_parent() {
        let err = validate_relative_path("../tmp", "cwd").unwrap_err();
        assert!(matches!(err, ValidationError::PathHasParent { .. }));
    }
}
