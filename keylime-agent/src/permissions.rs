// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use crate::error::{Error, Result};
use libc::{c_char, c_int, gid_t, uid_t};
use log::*;
use std::os::unix::ffi::OsStrExt;
use std::{
    convert::{TryFrom, TryInto},
    ffi::CString,
    io,
    path::Path,
    ptr,
};

pub(crate) struct UserIds {
    passwd: libc::passwd,
    group: libc::group,
}

pub(crate) fn get_gid() -> gid_t {
    unsafe { libc::getgid() }
}

pub(crate) fn get_uid() -> uid_t {
    unsafe { libc::getuid() }
}

pub(crate) fn get_euid() -> uid_t {
    unsafe { libc::geteuid() }
}

impl TryFrom<&str> for UserIds {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        let parts = value.split(':').collect::<Vec<&str>>();

        if parts.len() != 2 {
            let e = format!("Invalid parameter format: {value} cannot be parsed as 'user:group'");
            error!("{}", e);
            return Err(Error::Conversion(e));
        }

        let user = parts[0];
        let group = parts[1];

        // Get gid from group name
        let grnam = if let Ok(g_cstr) = CString::new(group.as_bytes()) {
            let p = unsafe { libc::getgrnam(g_cstr.as_ptr()) };
            if p.is_null() {
                let e = io::Error::last_os_error();
                error!("Could not get group {}: {}", group, e);
                return Err(Error::Conversion(e.to_string()));
            }
            unsafe { (*p) }
        } else {
            return Err(Error::Conversion(format!(
                "Failed to convert {group} to CString"
            )));
        };

        // Get uid from user name
        let passwd = if let Ok(u_cstr) = CString::new(user.as_bytes()) {
            let p = unsafe { libc::getpwnam(u_cstr.as_ptr()) };
            if p.is_null() {
                let e = io::Error::last_os_error();
                error!("Could not get user {}: {}", user, e);
                return Err(Error::Conversion(e.to_string()));
            }
            unsafe { (*p) }
        } else {
            return Err(Error::Conversion(format!(
                "Failed to convert {user} to CString"
            )));
        };

        Ok(UserIds {
            passwd,
            group: grnam,
        })
    }
}

// Drop the process privileges and run under the provided user and group.  The correct order of
// operations are: drop supplementary groups, set gid, then set uid.
// See: POS36-C and CWE-696
pub(crate) fn run_as(user_group: &str) -> Result<()> {
    let ids: UserIds = user_group.try_into()?;

    // Set gid
    if unsafe { libc::setgid(ids.group.gr_gid) } != 0 {
        let e = io::Error::last_os_error();
        error!("Could not set group id: {}", e);
        return Err(Error::Permission);
    }

    // Get list of supplementary groups
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
            error!("Could not get list of supplementary groups");
            return Err(Error::Permission);
        }
    }

    // Set supplementary groups
    if unsafe { libc::setgroups(ngroups as usize, sup_groups.as_ptr()) } != 0
    {
        let e = io::Error::last_os_error();
        error!("Could not set supplementary groups: {}", e);
        return Err(Error::Permission);
    }

    // Set uid
    if unsafe { libc::setuid(ids.passwd.pw_uid) } != 0 {
        let e = io::Error::last_os_error();
        error!("Could not set user id: {}", e);
        return Err(Error::Permission);
    }

    info!("Dropped privileges to run as {}", user_group);

    Ok(())
}

pub(crate) fn chown(user_group: &str, path: &Path) -> Result<()> {
    let ids: UserIds = user_group.try_into()?;

    // check privilege
    if get_euid() != 0 {
        error!(
            "Privilege level unable to change file {} ownership",
            path.display()
        );
        return Err(Error::Permission);
    }

    // change directory owner
    let c_path = CString::new(path.as_os_str().as_bytes())?;
    if unsafe {
        libc::chown(c_path.as_ptr(), ids.passwd.pw_uid, ids.group.gr_gid)
    } != 0
    {
        error!("Failed to change file {} owner.", path.display());
        return Err(Error::Permission);
    }

    info!("Changed file {} owner to {}.", path.display(), user_group);
    Ok(())
}
