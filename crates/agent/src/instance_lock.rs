//! One agent per data dir.
//!
//! `p2claw run` takes an exclusive `flock` on `<data_dir>/agent.lock`
//! and holds it for the life of the process; the file records the
//! holder's pid. A second `run` sees the lock is held and refuses
//! instead of starting up beside the first. A second agent used to
//! replace the first agent's local-API socket and then delete it on
//! exit, leaving the first agent running with no socket for the CLI.
//!
//! The kernel drops the lock when the holder exits, however it exits,
//! so a crash can't leave the lock stuck. The fd is close-on-exec, so
//! a binary swapped in by an upgrade doesn't inherit it.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

/// Held for as long as the agent runs. Dropping it releases the lock.
#[derive(Debug)]
pub struct InstanceLock {
    _lock: Flock<File>,
}

#[derive(Debug)]
pub enum Acquire {
    Acquired(InstanceLock),
    /// Another process holds the lock. Carries its pid, when the
    /// file records one.
    HeldBy(Option<u32>),
}

/// Take the lock at `path` without waiting. The parent directory must
/// already exist (the identity key's load creates the data dir).
pub fn try_acquire(path: &Path) -> io::Result<Acquire> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(mut lock) => {
            lock.set_len(0)?;
            lock.seek(SeekFrom::Start(0))?;
            writeln!(lock, "{}", std::process::id())?;
            Ok(Acquire::Acquired(InstanceLock { _lock: lock }))
        }
        Err((mut file, e)) if e == Errno::EWOULDBLOCK => {
            let mut s = String::new();
            let _ = file.read_to_string(&mut s);
            Ok(Acquire::HeldBy(s.trim().parse().ok()))
        }
        Err((_, e)) => Err(io::Error::from(e)),
    }
}

/// The pid of a running agent that holds the lock at `path`, if one does.
/// Doesn't create anything: a missing data dir or lock file means no agent.
/// Returns `Some(None)` when the lock is held but no pid is recorded.
///
/// Probes with a shared lock that it drops at once. An agent starting
/// in that instant would see the lock held and exit; its service
/// manager starts it again.
pub fn holder(path: &Path) -> Option<Option<u32>> {
    let mut file = File::open(path).ok()?;
    match Flock::lock(file.try_clone().ok()?, FlockArg::LockSharedNonblock) {
        // Nobody holds it exclusively; our shared lock drops right here.
        Ok(_) => None,
        Err((_, e)) if e == Errno::EWOULDBLOCK => {
            let mut s = String::new();
            let _ = file.read_to_string(&mut s);
            Some(s.trim().parse().ok())
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_sees_the_first_holder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.lock");

        let first = match try_acquire(&path).unwrap() {
            Acquire::Acquired(l) => l,
            Acquire::HeldBy(_) => panic!("first acquire should succeed"),
        };
        assert_eq!(holder(&path), Some(Some(std::process::id())));
        match try_acquire(&path).unwrap() {
            Acquire::HeldBy(pid) => assert_eq!(pid, Some(std::process::id())),
            Acquire::Acquired(_) => panic!("second acquire should see the lock held"),
        }

        drop(first);
        assert_eq!(holder(&path), None);
        assert!(matches!(try_acquire(&path).unwrap(), Acquire::Acquired(_)));
    }

    #[test]
    fn no_lock_file_means_no_holder() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(holder(&dir.path().join("agent.lock")), None);
        assert_eq!(holder(&dir.path().join("missing/agent.lock")), None);
    }
}
