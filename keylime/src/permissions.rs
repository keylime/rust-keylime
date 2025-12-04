// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use libc::{c_int, gid_t, uid_t};
use log::*;
use std::{
    convert::{TryFrom, TryInto},
    ffi::CString,
    fs, io,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PermissionError {
    /// Failed to change file ownership
    #[error("Failed to change file {0} owner")]
    ChOwn(String),

    /// Failed to convert group name to CString
    #[error("Failed to convert group {0} to CString")]
    CStringConversion(String),

    /// Could not get supplementary groups
    #[error("Could not get list of supplementary groups")]
    GetGroupList(#[source] io::Error),

    /// Error getting GID from group name
    #[error("Could not get GID from group name {group}: {error:?}")]
    GetGrNam {
        group: String,
        #[source]
        error: io::Error,
    },

    /// Error getting UID from user name
    #[error("Could not get UID from user name {user}: {error:?}")]
    GetPWNam {
        user: String,
        #[source]
        error: io::Error,
    },

    /// Invalid parameter error
    #[error(
        "Invalid parameter format: {value} cannot be parsed as 'user:group'"
    )]
    InvalidInput { value: String },

    /// Not enough permission
    #[error("Privilege is not enough to change file {0} ownership")]
    NotRoot(String),

    /// Null string provided
    #[error("Null string")]
    NullString(#[from] std::ffi::NulError),

    /// Error setting group ID
    #[error("Could not set GID: {0:?}")]
    SetGID(#[source] io::Error),

    /// Error setting supplementary groups
    #[error("Could not set supplementary groups: {0:?}")]
    SetGroups(#[source] io::Error),

    /// Error setting mode for file
    #[error("Could not set permissions of {path} to mode {mode:#o}")]
    SetMode {
        path: String,
        mode: u32,
        #[source]
        source: io::Error,
    },

    /// Error setting UID
    #[error("Could not set UID: {0:?}")]
    SetUID(#[source] io::Error),
}

pub struct UserIds {
    passwd: libc::passwd,
    group: libc::group,
}

pub fn get_gid() -> gid_t {
    unsafe { libc::getgid() }
}

pub fn get_uid() -> uid_t {
    unsafe { libc::getuid() }
}

pub fn get_euid() -> uid_t {
    unsafe { libc::geteuid() }
}

impl TryFrom<&str> for UserIds {
    type Error = PermissionError;

    fn try_from(value: &str) -> Result<Self, PermissionError> {
        let parts = value.split(':').collect::<Vec<&str>>();

        if parts.len() != 2 {
            return Err(PermissionError::InvalidInput {
                value: value.to_string(),
            });
        }

        let user = parts[0];
        let group = parts[1];

        // Get gid from group name
        let grnam = if let Ok(g_cstr) = CString::new(group.as_bytes()) {
            let p = unsafe { libc::getgrnam(g_cstr.as_ptr()) };
            if p.is_null() {
                let e = io::Error::last_os_error();
                return Err(PermissionError::GetGrNam {
                    group: group.to_string(),
                    error: e,
                });
            }
            unsafe { *p }
        } else {
            return Err(PermissionError::CStringConversion(
                group.to_string(),
            ));
        };

        // Get uid from user name
        let passwd = if let Ok(u_cstr) = CString::new(user.as_bytes()) {
            let p = unsafe { libc::getpwnam(u_cstr.as_ptr()) };
            if p.is_null() {
                let e = io::Error::last_os_error();
                return Err(PermissionError::GetPWNam {
                    user: user.to_string(),
                    error: e,
                });
            }
            unsafe { *p }
        } else {
            return Err(PermissionError::CStringConversion(user.to_string()));
        };

        Ok(UserIds {
            passwd,
            group: grnam,
        })
    }
}

/// Drop process privileges to run as the specified user and group
///
/// This function performs a secure privilege drop following POSIX standards
/// and security best practices (POS36-C, CWE-696). The operations MUST be
/// performed in this exact order:
/// 1. Get supplementary groups (before dropping privileges)
/// 2. Set supplementary groups (before setgid)
/// 3. Set GID (before setuid)
/// 4. Set UID (last - irreversible)
///
/// # Arguments
///
/// * `user_group` - User and group in "user:group" format (e.g., "keylime:keylime")
///
/// # Returns
///
/// * `Ok(())` if privileges were successfully dropped
/// * `Err(PermissionError)` if any step fails
///
/// # Errors
///
/// This function will return an error if:
/// - The user or group name cannot be found (`GetPWNam`, `GetGrNam`)
/// - The supplementary groups cannot be retrieved (`GetGroupList`)
/// - Setting supplementary groups fails (`SetGroups`)
/// - Setting GID fails (`SetGID`)
/// - Setting UID fails (`SetUID`)
///
/// # Security
///
/// This function is security-critical. The calling process must have root
/// privileges (UID 0) for this to succeed. After `setuid()`, the privilege
/// drop is irreversible - the process cannot regain root privileges.
///
/// The order of operations is critical to prevent privilege retention on error.
/// See CERT C Coding Standard POS36-C and CWE-696 for details.
///
/// # Example
///
/// ```no_run
/// use keylime::permissions::run_as;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Must be running as root (UID 0)
/// run_as("keylime:keylime")?;
/// // Process is now running as keylime:keylime
/// # Ok(())
/// # }
/// ```
pub fn run_as(user_group: &str) -> Result<(), PermissionError> {
    let ids: UserIds = user_group.try_into()?;

    // Get list of supplementary groups (must be done before dropping privileges)
    let mut sup_groups: [gid_t; 32] = [0u32; 32];
    let mut ngroups: c_int = 32;
    if unsafe {
        libc::getgrouplist(
            ids.passwd.pw_name,
            ids.group.gr_gid,
            sup_groups.as_mut_ptr(),
            &mut ngroups,
        )
    } < 0
    {
        // Allocate a Vec and try again
        let mut sup_groups: Vec<gid_t> = Vec::with_capacity(ngroups as usize);
        if unsafe {
            libc::getgrouplist(
                ids.passwd.pw_name,
                ids.group.gr_gid,
                sup_groups.as_mut_ptr(),
                &mut ngroups,
            )
        } < 0
        {
            let e = io::Error::last_os_error();
            return Err(PermissionError::GetGroupList(e));
        }

        // Sanity check: Verify group count is reasonable
        // A very large number of groups could indicate a system issue or attack
        const MAX_REASONABLE_GROUPS: c_int = 1024;
        if !(0..=MAX_REASONABLE_GROUPS).contains(&ngroups) {
            let e = io::Error::other(format!(
                "getgrouplist returned unreasonable group count: {}. \
                 Valid range is 0-{}. This indicates a system issue or potential attack.",
                ngroups,
                MAX_REASONABLE_GROUPS
            ));
            return Err(PermissionError::GetGroupList(e));
        }

        // Verify the buffer was large enough
        // getgrouplist may update ngroups even on success
        if ngroups as usize > sup_groups.capacity() {
            let e = io::Error::other(format!(
                "getgrouplist buffer overflow: returned {} groups but capacity is {}. \
                 This indicates a serious system issue.",
                ngroups,
                sup_groups.capacity()
            ));
            return Err(PermissionError::GetGroupList(e));
        }
    }

    // Set supplementary groups (must be done before setgid)
    if unsafe { libc::setgroups(ngroups as usize, sup_groups.as_ptr()) } != 0
    {
        let e = io::Error::last_os_error();
        return Err(PermissionError::SetGroups(e));
    }

    // Set gid (must be done before setuid)
    if unsafe { libc::setgid(ids.group.gr_gid) } != 0 {
        let e = io::Error::last_os_error();
        return Err(PermissionError::SetGID(e));
    }

    // Set uid (must be done last, as it's irreversible)
    if unsafe { libc::setuid(ids.passwd.pw_uid) } != 0 {
        let e = io::Error::last_os_error();
        return Err(PermissionError::SetUID(e));
    }

    // CRITICAL: Verify privilege drop was successful and irreversible
    let current_uid = unsafe { libc::getuid() };
    let current_euid = unsafe { libc::geteuid() };
    if current_uid != ids.passwd.pw_uid || current_euid != ids.passwd.pw_uid {
        return Err(PermissionError::SetUID(io::Error::other(
            format!("Privilege drop verification failed: uid={}, euid={}, expected={}",
                    current_uid, current_euid, ids.passwd.pw_uid)
        )));
    }

    // Verify we cannot regain root privileges
    if unsafe { libc::setuid(0) } == 0 {
        return Err(PermissionError::SetUID(io::Error::other(
            "CRITICAL: Process can still regain root privileges after dropping"
        )));
    }

    info!("Dropped privileges to run as {user_group}");

    Ok(())
}

pub fn chown(user_group: &str, path: &Path) -> Result<(), PermissionError> {
    let ids: UserIds = user_group.try_into()?;

    // check privilege
    if get_euid() != 0 {
        error!(
            "Privilege level unable to change file {} ownership",
            path.display()
        );
        return Err(PermissionError::NotRoot(path.display().to_string()));
    }

    // change directory owner
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    if unsafe {
        libc::chown(c_path.as_ptr(), ids.passwd.pw_uid, ids.group.gr_gid)
    } != 0
    {
        error!("Failed to change file {} owner.", path.display());
        return Err(PermissionError::ChOwn(path.display().to_string()));
    }

    info!("Changed file {} owner to {}.", path.display(), user_group);
    Ok(())
}

/// Set file permissions to the given mode
pub fn set_mode(path: &Path, mode: u32) -> Result<(), PermissionError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| {
        PermissionError::SetMode {
            path: path.display().to_string(),
            mode,
            source: e,
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{fs::File, io::Write};

    #[test]
    fn test_get_uid() {
        let _uid = get_uid();
    }

    #[test]
    fn test_get_gid() {
        let _gid = get_gid();
    }

    #[test]
    fn test_get_euid() {
        let _euid = get_euid();
    }

    #[test]
    fn test_chown() {
        // Only test chown when running as root
        if get_euid() == 0 {
            let temp_dir = tempfile::tempdir()
                .expect("failed to create temporary directory");
            let p = temp_dir.path().join("testfile.txt");
            let mut f = File::create(&p).expect("failed to create file");
            f.write_all(b"test content\n")
                .expect("failed to write to file");
            let r = chown("root:root", &p);
            assert!(r.is_ok());
        }
    }

    #[test]
    fn test_set_mode() {
        let temp_dir = tempfile::tempdir()
            .expect("failed to create temporary directory");
        let p = temp_dir.path().join("testfile.txt");
        let mut f = File::create(&p).expect("failed to create file");
        f.write_all(b"test content\n")
            .expect("failed to write to file");

        let r = set_mode(&p, 0o777);
        assert!(r.is_ok());
    }

    #[test]
    fn test_try_from_str_for_userids() {
        let r = UserIds::try_from("root:root");
        assert!(r.is_ok());
        let r = UserIds::try_from("invalid:root");
        assert!(r.is_err());
        let r = UserIds::try_from("root:invalid");
        assert!(r.is_err());
        let r = UserIds::try_from("invalid");
        assert!(r.is_err());
        let r = UserIds::try_from("invalid:invalid");
        assert!(r.is_err());
        let r = UserIds::try_from("");
        assert!(r.is_err());
        let r = UserIds::try_from(":invalid");
        assert!(r.is_err());
        let r = UserIds::try_from("invalid:");
        assert!(r.is_err());
    }
}
