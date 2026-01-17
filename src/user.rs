use std::ffi::{CStr, CString};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home_dir: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("user lookup failed for uid {uid}: {source}")]
    UserLookupFailed {
        uid: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("user with uid {uid} not found")]
    UserNotFound { uid: u32 },

    #[error("user lookup failed for name {name}: {source}")]
    UserNameLookupFailed {
        name: String,
        #[source]
        source: std::io::Error,
    },

    #[error("user {name} not found")]
    UserNameNotFound { name: String },

    #[error("group lookup failed for {name}: {source}")]
    GroupLookupFailed {
        name: String,
        #[source]
        source: std::io::Error,
    },

    #[error("group {name} not found")]
    GroupNotFound { name: String },

    #[error("invalid group name {name}")]
    InvalidGroupName { name: String },

    #[error("buffer too small for system lookup")]
    BufferTooSmall,
}

pub fn lookup_user(uid: u32) -> Result<UserInfo, UserError> {
    let buf_len = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buf_len = if buf_len < 0 { 1024 } else { buf_len as usize };

    loop {
        let mut buf = vec![0u8; buf_len];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        let ret = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };

        if ret == 0 {
            if result.is_null() {
                return Err(UserError::UserNotFound { uid });
            }

            let username = unsafe { CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned();
            let home_dir = unsafe { CStr::from_ptr(pwd.pw_dir) }
                .to_string_lossy()
                .into_owned();

            return Ok(UserInfo {
                username,
                uid: pwd.pw_uid,
                gid: pwd.pw_gid,
                home_dir: PathBuf::from(home_dir),
            });
        }

        if ret == libc::ERANGE {
            buf_len = buf_len.saturating_mul(2);
            if buf_len > 1024 * 1024 {
                return Err(UserError::BufferTooSmall);
            }
            continue;
        }

        return Err(UserError::UserLookupFailed {
            uid,
            source: std::io::Error::from_raw_os_error(ret),
        });
    }
}

pub fn lookup_user_by_name(name: &str) -> Result<UserInfo, UserError> {
    let c_name = CString::new(name).map_err(|_| UserError::UserNameNotFound {
        name: name.to_string(),
    })?;

    let buf_len = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buf_len = if buf_len < 0 { 1024 } else { buf_len as usize };

    loop {
        let mut buf = vec![0u8; buf_len];
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        let ret = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };

        if ret == 0 {
            if result.is_null() {
                return Err(UserError::UserNameNotFound {
                    name: name.to_string(),
                });
            }

            let username = unsafe { CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned();
            let home_dir = unsafe { CStr::from_ptr(pwd.pw_dir) }
                .to_string_lossy()
                .into_owned();

            return Ok(UserInfo {
                username,
                uid: pwd.pw_uid,
                gid: pwd.pw_gid,
                home_dir: PathBuf::from(home_dir),
            });
        }

        if ret == libc::ERANGE {
            buf_len = buf_len.saturating_mul(2);
            if buf_len > 1024 * 1024 {
                return Err(UserError::BufferTooSmall);
            }
            continue;
        }

        return Err(UserError::UserNameLookupFailed {
            name: name.to_string(),
            source: std::io::Error::from_raw_os_error(ret),
        });
    }
}

pub fn lookup_group_gid(name: &str) -> Result<u32, UserError> {
    let c_name = CString::new(name).map_err(|_| UserError::InvalidGroupName {
        name: name.to_string(),
    })?;

    let buf_len = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    let mut buf_len = if buf_len < 0 { 1024 } else { buf_len as usize };

    loop {
        let mut buf = vec![0u8; buf_len];
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();

        let ret = unsafe {
            libc::getgrnam_r(
                c_name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };

        if ret == 0 {
            if result.is_null() {
                return Err(UserError::GroupNotFound {
                    name: name.to_string(),
                });
            }

            return Ok(grp.gr_gid);
        }

        if ret == libc::ERANGE {
            buf_len = buf_len.saturating_mul(2);
            if buf_len > 1024 * 1024 {
                return Err(UserError::BufferTooSmall);
            }
            continue;
        }

        return Err(UserError::GroupLookupFailed {
            name: name.to_string(),
            source: std::io::Error::from_raw_os_error(ret),
        });
    }
}
