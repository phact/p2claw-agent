//! Self-FD counting for the agent.
//!
//! Used by the local-API accept-loop EMFILE handler to surface the
//! current FD count in the fatal log line and (eventually) by a
//! `/metrics` gauge if we ever expose one for the agent. Cross-
//! platform across the two targets we ship to (Linux + macOS) via the
//! `/proc/self/fd` and `/dev/fd` directory listings respectively —
//! both kernels surface the calling process's open FDs as directory
//! entries when the process itself reads them.
//!
//! On Linux the count includes:
//! - the three standard FDs (stdin/out/err) — almost always 3
//! - any anonymous-inode FDs (epoll, eventfd, signalfd, timerfd…)
//! - sockets (TCP, UDP, Unix), pipes, regular files
//! - the `read_dir` call's own opened FD, which we subtract
//!
//! macOS surfaces a similar set via `/dev/fd`. The numbers won't
//! match Linux exactly because the kernels lay things out
//! differently (e.g. macOS gives each tokio reactor a different set
//! of kqueue FDs) but trends are what matter for leak detection,
//! not absolute parity.
//!
//! Errors return `None` rather than panic — counting FDs is best-
//! effort observability, not correctness. A logged FD count of
//! `unknown` still beats no log at all on EMFILE.

/// Best-effort count of FDs currently open by the calling process.
/// Returns `None` on platforms without a per-process FD directory or
/// when the directory read itself fails.
///
/// The count is **inclusive of the directory FD that `read_dir`
/// opens to enumerate** — we subtract 1 to compensate so callers see
/// a steady-state reading. (Without the subtraction, every call
/// reports `actual + 1`, which obscures the real value when comparing
/// readings before/after work.)
pub fn fd_count() -> Option<usize> {
    let path = fd_dir_path()?;
    let n = std::fs::read_dir(path).ok()?.count();
    // The directory itself was opened to read. Don't double-count.
    Some(n.saturating_sub(1))
}

fn fd_dir_path() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("/proc/self/fd")
    } else if cfg!(target_os = "macos") {
        Some("/dev/fd")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On the supported platforms, `fd_count()` must succeed and
    /// return a plausibly small steady-state number — the test
    /// process opens at least stdin/stdout/stderr + a few tokio
    /// internals, but should be well under a thousand.
    #[test]
    fn returns_a_plausible_count_on_supported_platforms() {
        let n = fd_count();
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            let n = n.expect("fd_count must succeed on Linux/macOS");
            assert!(n >= 3, "expected at least stdin/stdout/stderr; got {n}");
            // Generous upper bound — no test should hold thousands
            // of FDs. If this trips, something has gone very wrong.
            assert!(n < 4096, "implausibly large FD count: {n}");
        } else {
            assert!(n.is_none(), "unsupported platform should return None");
        }
    }

    /// `fd_count()` returns a plausible value across a process FD
    /// state change. We deliberately do NOT assert exact arithmetic
    /// (`before + 8 == with_files`) — cargo runs tests in parallel
    /// and other threads independently open/close FDs during the
    /// observation window, so any tight assertion races the rest
    /// of the test suite and flakes intermittently. The meaningful
    /// end-to-end check (FD count returns to baseline after the
    /// agent does its work) lives in
    /// `local_api::tests::local_api_does_not_leak_fds_across_n_requests`,
    /// which warms up before sampling and has its own slack budget.
    /// Here we just verify the helper changes its reading at all
    /// when the process FD table mutates.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn reflects_changes_in_process_fd_table() {
        let before = fd_count().expect("fd_count");
        let files: Vec<_> = (0..32)
            .map(|_| tempfile::tempfile().expect("tempfile"))
            .collect();
        let with_files = fd_count().expect("fd_count");
        // 32 fds opened — even with worst-case parallel-test churn
        // closing some fds during the window, the net delta should
        // be visible above zero. If it isn't, fd_count() is broken.
        assert!(
            with_files > before,
            "fd_count() must visibly increase after opening 32 fds \
             (before={before}, with_files={with_files})"
        );
        // Hold `files` until here so the open assertion isn't racing
        // their drop. Post-drop is not asserted.
        drop(files);
    }
}
