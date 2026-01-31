use anyhow::Result;
use nix::unistd::{geteuid, getgid, getuid, setresuid, Uid};
use std::{env, io};

pub fn invoker_permissions() -> Result<(u32, u32)> {
    let uid = match env::var("SUDO_UID").ok() {
        Some(uid) => uid.parse()?,
        None => getuid().as_raw(), // if invoking with setuid, use ruid
    };
    let gid = match env::var("SUDO_GID").ok() {
        Some(gid) => gid.parse()?,
        None => getgid().as_raw(), // if invoking with setuid, use rgid
    };
    Ok((uid, gid))
}

/// Safely drops effective privileges to the Real User ID while held.
/// Restores them to the Saved UID (root) when dropped.
pub struct PrivGuard {
    saved_euid: Uid,
}

impl PrivGuard {
    pub fn drop_to_user() -> Result<Self> {
        let ruid = getuid();
        let euid = geteuid();
        // setresuid(real, effective, saved)
        setresuid(ruid, ruid, euid).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(PrivGuard { saved_euid: euid })
    }
}

impl Drop for PrivGuard {
    fn drop(&mut self) {
        let ruid = getuid();
        // Restore effective UID to the saved UID (root)
        let _ = setresuid(ruid, self.saved_euid, self.saved_euid);
    }
}
