use anyhow::{anyhow, Result};
use nix::unistd::{geteuid, getgid, getuid, setresuid, Uid};
use std::{env, io, path::PathBuf};

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

pub fn resolve_executable(executable: &str) -> Result<PathBuf> {
    let path_obj = PathBuf::from(executable);
    if path_obj.is_absolute() || executable.contains('/') {
        if path_obj.exists() {
            return Ok(path_obj);
        }
        return Err(anyhow!("executable not found at specified path"));
    }

    let path = env::var("PATH")?;
    for p in path.split(':') {
        let executable_path = PathBuf::from(p).join(executable);
        if executable_path.exists() {
            return Ok(executable_path);
        }
    }
    Err(anyhow!("executable not found"))
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
