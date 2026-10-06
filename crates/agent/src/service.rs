//! `p2claw service install / uninstall / status` — keep the daemon
//! alive across logout / reboot via the host's user-scope service
//! mechanism. macOS uses `launchd`
//! (`LaunchAgents/dev.p2claw.agent.plist`); Linux uses
//! `systemd --user` (`~/.config/systemd/user/p2claw-agent.service`).
//! Windows is unsupported.
//!
//! The unit/plist bakes the absolute binary path resolved at install
//! time, so the service survives `$PATH` changes; a relocation needs
//! a re-install.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("`$HOME` is not set — cannot resolve service install path")]
    MissingHome,
    #[error("could not determine the running binary's path: {0}")]
    NoCurrentExe(#[source] io::Error),
    #[error("`{bin}` is not present at `{path}`")]
    BinNotFound { bin: &'static str, path: String },
    #[error("`{tool} {action}` exited with status {status}: {stderr}")]
    ToolFailed {
        tool: &'static str,
        action: &'static str,
        status: String,
        stderr: String,
    },
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[error("`p2claw service` is not supported on this platform")]
    UnsupportedPlatform,
}

/// End-of-`service install` UX banner. `disable_magicdns = true` is
/// the publish-only mode (no SNI listener / DNS resolver / CA root);
/// `false` is the full `--magicdns` install.
fn print_install_banner(disable_magicdns: bool) {
    println!();
    if disable_magicdns {
        println!("✓ p2claw agent installed.");
        println!();
        println!("  Apps you publish will be reachable at");
        println!("  https://app-<alias>.<parent_domain>/ from anywhere —");
        println!("  browsers via WebRTC, CLI / webhooks / file uploads via the");
        println!("  edge tunnel. No further setup needed.");
        println!();
        println!("  Optional outbound upgrade: if you also want `curl");
        println!("  https://app-<other>.<parent>/...` from this machine to dial");
        println!("  other machines directly (instead of via the public edge), re-run");
        println!("  with the MagicDNS scaffolding:");
        println!("    sudo p2claw service install --magicdns");
    } else {
        println!("✓ p2claw agent installed (with MagicDNS).");
        println!();
        println!("  Apps you publish will be reachable at");
        println!("  https://app-<alias>.<parent_domain>/ from anywhere.");
        println!();
        println!("  Local apps on this machine can also dial other machines via");
        println!("  `curl https://other-alias.<parent>/...` (direct P2P, end-to-");
        println!("  end encrypted; bypasses the public edge).");
    }
}

/// Banner printed when the user passed `--magicdns` but declined the
/// elevation prompt: re-run with sudo, or fall back to the default
/// publish-only install.
pub fn print_sudo_declined_banner() {
    eprintln!();
    eprintln!("✗ `--magicdns` needs root once to set up the resolver / 443 listener.");
    eprintln!();
    eprintln!("  You declined the elevation prompt. Two ways forward:");
    eprintln!();
    eprintln!("  • Re-run with sudo to enable MagicDNS:");
    eprintln!("      sudo p2claw service install --magicdns");
    eprintln!();
    eprintln!("  • Drop `--magicdns` and install in the default mode (apps");
    eprintln!("    you publish stay reachable from anywhere; `curl");
    eprintln!("    https://*.<parent_domain>/` from THIS machine routes via");
    eprintln!("    the public edge instead of direct P2P):");
    eprintln!("      p2claw service install");
}

/// Outcome of a service-config drift check. Run after auto-upgrade
/// (and on demand via `p2claw service-config --check`) so plist /
/// unit changes shipped with new binaries propagate without a
/// manual `service install` re-run.
#[derive(Debug, Clone)]
pub struct DriftReport {
    pub path: PathBuf,
    pub state: DriftState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftState {
    /// No file at `path`; `service install` hasn't been run.
    NotInstalled,
    /// On-disk file matches the current render byte-for-byte.
    Clean,
    /// On-disk file differs from the current render. `rewrote = true`
    /// when the caller asked us to fix it (wrote + reloaded);
    /// `false` for a read-only check.
    Drifted { rewrote: bool },
}

/// Options for `p2claw service install`.
pub struct InstallOpts {
    /// Absolute path to the `p2claw` binary the service should run.
    /// Defaults to [`std::env::current_exe`].
    pub bin_path: Option<PathBuf>,
    /// Write the plist/unit but skip the activation step (`launchctl
    /// bootstrap` / `systemctl --user enable --now`). Useful for
    /// staging in CI.
    pub no_start: bool,
    /// Publish-only mode: bake `P2CLAW_AGENT_DISABLE_MAGICDNS=true`
    /// into the agent env so it skips the SNI listener, DNS resolver,
    /// and CA-trust hookup at startup. CLI dispatch owns the
    /// user-facing default and elevation/fallback logic.
    pub disable_magicdns: bool,
}

/// Resolve the absolute binary path the service should reference.
fn resolve_bin_path(override_: Option<PathBuf>) -> Result<PathBuf, ServiceError> {
    let p = match override_ {
        Some(p) => p,
        None => env::current_exe().map_err(ServiceError::NoCurrentExe)?,
    };
    // Canonicalise so the unit/plist stores the resolved path even
    // if the binary was launched via a symlink. Fall back to the
    // raw path when canonicalise fails (e.g. `--bin-path` points at
    // a future location).
    Ok(p.canonicalize().unwrap_or(p))
}

/// Resolve `$HOME`, falling back to the passwd entry for the
/// effective uid. The fallback matters under HOME-stripped
/// supervisors (systemd, cron, sudo without `-H`).
fn home_dir() -> Result<PathBuf, ServiceError> {
    if let Some(h) = env::var_os("HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h));
        }
    }
    let uid = nix::unistd::Uid::effective();
    nix::unistd::User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| u.dir)
        .ok_or(ServiceError::MissingHome)
}

fn ensure_parent(path: &Path) -> Result<(), ServiceError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| ServiceError::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    Ok(())
}

fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<(), ServiceError> {
    ensure_parent(path)?;
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp_path)
            .map_err(|e| ServiceError::Io {
                path: tmp_path.display().to_string(),
                source: e,
            })?;
        f.write_all(contents.as_bytes())
            .map_err(|e| ServiceError::Io {
                path: tmp_path.display().to_string(),
                source: e,
            })?;
        f.sync_all().map_err(|e| ServiceError::Io {
            path: tmp_path.display().to_string(),
            source: e,
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode; // unused on non-unix
        fs::write(&tmp_path, contents).map_err(|e| ServiceError::Io {
            path: tmp_path.display().to_string(),
            source: e,
        })?;
    }

    fs::rename(&tmp_path, path).map_err(|e| ServiceError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

fn run_tool(tool: &'static str, action: &'static str, args: &[&str]) -> Result<(), ServiceError> {
    let out = Command::new(tool)
        .args(args)
        .output()
        .map_err(|e| ServiceError::ToolFailed {
            tool,
            action,
            status: format!("spawn failed: {e}"),
            stderr: String::new(),
        })?;
    if !out.status.success() {
        return Err(ServiceError::ToolFailed {
            tool,
            action,
            status: out.status.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(())
}

/// Install-time `P2CLAW_RELEASE_REPO`, kept only when it looks like
/// `owner/repo` so it can be written verbatim into a unit or plist.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn release_repo_from_env() -> Option<String> {
    let v = env::var(crate::auto_upgrade::RELEASE_REPO_ENV).ok()?;
    let v = v.trim();
    if is_valid_repo_slug(v) {
        Some(v.to_string())
    } else {
        if !v.is_empty() {
            warn!(value = %v, "ignoring P2CLAW_RELEASE_REPO: expected <owner>/<repo>");
        }
        None
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn is_valid_repo_slug(v: &str) -> bool {
    let ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    matches!(v.split_once('/'), Some((owner, repo)) if ok(owner) && ok(repo))
}

/// Env baked into the user-scope unit / plist.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn service_env(disable_magicdns: bool, release_repo: Option<&str>) -> Vec<(&'static str, &str)> {
    let mut env = Vec::new();
    if disable_magicdns {
        env.push(("P2CLAW_AGENT_DISABLE_MAGICDNS", "true"));
    }
    if let Some(repo) = release_repo {
        env.push((crate::auto_upgrade::RELEASE_REPO_ENV, repo));
    }
    env
}

/// `P2CLAW_RELEASE_REPO` value from an installed plist, if any.
#[cfg(any(target_os = "macos", test))]
fn plist_release_repo(plist: &str) -> Option<String> {
    let key = format!("<key>{}</key>", crate::auto_upgrade::RELEASE_REPO_ENV);
    let rest = &plist[plist.find(&key)? + key.len()..];
    let rest = &rest[rest.find("<string>")? + "<string>".len()..];
    let v = &rest[..rest.find("</string>")?];
    is_valid_repo_slug(v).then(|| v.to_string())
}

// ─────────────────────────────────────────────────────────────────────
// macOS — launchd user agent
// ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    const LABEL: &str = "dev.p2claw.agent";
    const PLIST_FILENAME: &str = "dev.p2claw.agent.plist";

    fn plist_path() -> Result<PathBuf, ServiceError> {
        Ok(home_dir()?
            .join("Library/LaunchAgents")
            .join(PLIST_FILENAME))
    }

    fn log_path() -> Result<PathBuf, ServiceError> {
        Ok(home_dir()?.join("Library/Logs/p2claw.log"))
    }

    fn target() -> String {
        // Modern launchd domain triplet `gui/<uid>/<label>`.
        format!("gui/{}/{}", crate::config::current_uid(), LABEL)
    }

    fn domain() -> String {
        format!("gui/{}", crate::config::current_uid())
    }

    fn render_plist(bin_path: &Path, log_file: &Path, extra_env: &[(&str, &str)]) -> String {
        // `SoftResourceLimits.NumberOfFiles=65536` raises the FD
        // ceiling above macOS's 256 default — buys alerting time
        // before EMFILE bites if something leaks.
        let extra_env_lines = extra_env
            .iter()
            .map(|(k, v)| format!("        <key>{k}</key>\n        <string>{v}</string>"))
            .collect::<Vec<_>>()
            .join("\n");
        let extra_env_block = if extra_env_lines.is_empty() {
            String::new()
        } else {
            format!("\n{extra_env_lines}")
        };
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>{extra_env_block}
    </dict>
</dict>
</plist>
"#,
            label = LABEL,
            bin = bin_path.display(),
            log = log_file.display(),
            extra_env_block = extra_env_block,
        )
    }

    pub fn install(opts: InstallOpts) -> Result<(), ServiceError> {
        let bin = resolve_bin_path(opts.bin_path)?;
        if !bin.exists() {
            return Err(ServiceError::BinNotFound {
                bin: "p2claw",
                path: bin.display().to_string(),
            });
        }
        let disable_magicdns = opts.disable_magicdns;
        let plist = plist_path()?;
        let log = log_path()?;
        ensure_parent(&log)?; // `~/Library/Logs/` usually exists, but be safe.

        // Bake the env var only when explicitly disabling MagicDNS.
        // A user-scope install with MagicDNS on can't bind 443; the
        // CLI is responsible for preventing that combination from
        // reaching this function.
        let release_repo = release_repo_from_env();
        let extra_env = service_env(disable_magicdns, release_repo.as_deref());
        let body = render_plist(&bin, &log, &extra_env);
        write_atomic(&plist, &body, 0o644)?;

        println!("wrote {}", plist.display());
        println!("logs   {}", log.display());

        if opts.no_start {
            println!("(--no-start) skipped `launchctl bootstrap`. Load later with:");
            println!("  launchctl bootstrap {} {}", domain(), plist.display());
            print_install_banner(disable_magicdns);
            return Ok(());
        }

        // Best-effort tear-down; `bootout` returns non-zero on a
        // clean install where nothing's loaded.
        let _ = run_tool(
            "launchctl",
            "bootout (best-effort)",
            &["bootout", &target()],
        );

        // `launchctl bootstrap gui/<uid>` needs an Aqua / GUI
        // session. Outside one (SSH, some tmux contexts) launchctl
        // returns 125 / "Domain does not support specified action".
        // The plist is already written, so we surface a "load it
        // from desktop Terminal" message and still exit success.
        let bootstrap_result = run_tool(
            "launchctl",
            "bootstrap",
            &["bootstrap", &domain(), plist.to_str().unwrap_or("")],
        );
        match bootstrap_result {
            Ok(()) => {
                // Re-enable in case bootout left it `disabled`;
                // enable is idempotent.
                let _ = run_tool("launchctl", "enable", &["enable", &target()]);
                println!("loaded {} via launchctl", LABEL);
                println!("status: p2claw service status");
                print_install_banner(disable_magicdns);
                Ok(())
            }
            Err(ServiceError::ToolFailed { status, stderr, .. })
                if status.contains("125")
                    || stderr.contains("125")
                    || stderr.contains("Domain does not support") =>
            {
                println!();
                println!("⚠ launchctl couldn't load the agent in this session.");
                println!("  This usually means you're in an SSH or non-desktop session.");
                println!();
                println!("  The LaunchAgent plist was written successfully. To finish:");
                println!();
                println!("  • Open Terminal.app from your desktop (NOT via SSH / tmux),");
                println!("    then run:");
                println!("      launchctl bootstrap {} {}", domain(), plist.display());
                println!();
                println!("  • Or simply log out + log back in — macOS auto-loads");
                println!("    LaunchAgents at session start.");
                print_install_banner(disable_magicdns);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn uninstall() -> Result<(), ServiceError> {
        let plist = plist_path()?;
        // Best-effort bootout — proceed to remove the plist either way.
        if let Err(e) = run_tool("launchctl", "bootout", &["bootout", &target()]) {
            warn!(error = %e, "launchctl bootout failed (continuing to remove plist)");
        }
        if plist.exists() {
            fs::remove_file(&plist).map_err(|e| ServiceError::Io {
                path: plist.display().to_string(),
                source: e,
            })?;
            println!("removed {}", plist.display());
        } else {
            println!("(no plist at {})", plist.display());
        }
        Ok(())
    }

    pub fn status() -> Result<(), ServiceError> {
        // `launchctl print` prints straight to stdout; pass it through.
        let st = Command::new("launchctl")
            .args(["print", &target()])
            .status()
            .map_err(|e| ServiceError::ToolFailed {
                tool: "launchctl",
                action: "print",
                status: format!("spawn failed: {e}"),
                stderr: String::new(),
            })?;
        if !st.success() {
            // `launchctl print` is non-zero when the service isn't
            // loaded; presence of the plist disambiguates "not
            // installed" from "installed but errored".
            let plist = plist_path()?;
            if !plist.exists() {
                println!(
                    "p2claw service is not installed (no plist at {})",
                    plist.display()
                );
            } else {
                println!(
                    "plist exists at {} but launchctl print failed — try `launchctl bootstrap {} {}`",
                    plist.display(), domain(), plist.display(),
                );
            }
        }
        Ok(())
    }

    pub fn check_drift(rewrite: bool) -> Result<DriftReport, ServiceError> {
        let plist = plist_path()?;
        let bin = resolve_bin_path(None)?;
        let log = log_path()?;
        let have = match fs::read_to_string(&plist) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(DriftReport {
                    path: plist,
                    state: DriftState::NotInstalled,
                });
            }
            Err(e) => {
                return Err(ServiceError::Io {
                    path: plist.display().to_string(),
                    source: e,
                });
            }
        };
        // Always expect the publish-only env line, and carry over any
        // release-repo override already in the plist so a rewrite
        // doesn't drop it.
        let release_repo = plist_release_repo(&have);
        let want = render_plist(&bin, &log, &service_env(true, release_repo.as_deref()));
        if have == want {
            return Ok(DriftReport {
                path: plist,
                state: DriftState::Clean,
            });
        }
        if !rewrite {
            return Ok(DriftReport {
                path: plist,
                state: DriftState::Drifted { rewrote: false },
            });
        }
        write_atomic(&plist, &want, 0o644)?;
        // Reload: best-effort bootout, then bootstrap.
        let _ = run_tool(
            "launchctl",
            "bootout (drift-rewrite)",
            &["bootout", &target()],
        );
        let _ = run_tool(
            "launchctl",
            "bootstrap (drift-rewrite)",
            &["bootstrap", &domain(), plist.to_str().unwrap_or("")],
        );
        Ok(DriftReport {
            path: plist,
            state: DriftState::Drifted { rewrote: true },
        })
    }
}

// ─────────────────────────────────────────────────────────────────────
// Linux — systemd --user
// ─────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    const UNIT_FILENAME: &str = "p2claw-agent.service";

    fn unit_path() -> Result<PathBuf, ServiceError> {
        // `$XDG_CONFIG_HOME` overrides; fall back to `~/.config`.
        let base = match env::var_os("XDG_CONFIG_HOME") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => home_dir()?.join(".config"),
        };
        Ok(base.join("systemd/user").join(UNIT_FILENAME))
    }

    fn render_unit(bin_path: &Path, extra_env: &[(&str, &str)]) -> String {
        // `LimitNOFILE=65536` raises the FD ceiling above typical
        // distro defaults (~4096) so alerting has room to fire
        // before EMFILE bites if something leaks.
        let extra_env_lines = extra_env
            .iter()
            .map(|(k, v)| format!("Environment={k}={v}"))
            .collect::<Vec<_>>()
            .join("\n");
        let extra_env_block = if extra_env_lines.is_empty() {
            String::new()
        } else {
            format!("\n{extra_env_lines}")
        };
        format!(
            "\
[Unit]
Description=p2claw agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={bin} run
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal{extra_env_block}

[Install]
WantedBy=default.target
",
            bin = bin_path.display(),
            extra_env_block = extra_env_block,
        )
    }

    pub fn install(opts: InstallOpts) -> Result<(), ServiceError> {
        let bin = resolve_bin_path(opts.bin_path)?;
        if !bin.exists() {
            return Err(ServiceError::BinNotFound {
                bin: "p2claw",
                path: bin.display().to_string(),
            });
        }
        let unit = unit_path()?;
        let disable_magicdns = opts.disable_magicdns;
        // Bake the env var only when explicitly disabling MagicDNS.
        // The CLI handles the setcap-via-sudo dance before reaching
        // here; this is just the post-decision input.
        let release_repo = release_repo_from_env();
        let extra_env = service_env(disable_magicdns, release_repo.as_deref());
        let body = render_unit(&bin, &extra_env);
        write_atomic(&unit, &body, 0o644)?;
        println!("wrote {}", unit.display());

        // Always reload — systemd caches unit definitions.
        run_tool("systemctl", "daemon-reload", &["--user", "daemon-reload"])?;

        ensure_linger();

        if opts.no_start {
            println!("(--no-start) skipped `enable --now`. Enable later with:");
            println!("  systemctl --user enable --now p2claw-agent.service");
            print_install_banner(disable_magicdns);
            return Ok(());
        }

        run_tool(
            "systemctl",
            "enable --now",
            &["--user", "enable", "--now", "p2claw-agent.service"],
        )?;

        println!("enabled and started p2claw-agent.service");
        println!("status: p2claw service status");
        println!("logs:   journalctl --user -u p2claw-agent.service -f");
        print_install_banner(disable_magicdns);
        Ok(())
    }

    /// A user-scope unit only runs while the user's systemd instance
    /// does, and that instance stops when the user's last session
    /// ends unless lingering is on — on a headless box the agent
    /// dies the moment the installing ssh session closes and every
    /// exposed app goes offline. Self-linger (`loginctl
    /// enable-linger` with no args) is polkit-allowed for active
    /// sessions on mainstream distros; when it isn't, fall back to
    /// telling the operator the sudo form.
    fn ensure_linger() {
        if linger_active() {
            return;
        }
        let attempted = Command::new("loginctl")
            .arg("enable-linger")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if attempted && linger_active() {
            println!("enabled lingering — the agent keeps running after you log out");
        } else {
            println!(
                "WARNING: lingering is OFF, so the agent (and every exposed app)\n\
                 stops when your last session ends. Fix once with:\n\
                 \x20 sudo loginctl enable-linger \"$USER\""
            );
        }
    }

    /// `loginctl enable-linger` drops a flag file named after the
    /// user; its presence is the ground truth `loginctl show-user`
    /// itself reports.
    fn linger_active() -> bool {
        let user = env::var("USER").ok().filter(|u| !u.is_empty()).or_else(|| {
            Command::new("id")
                .arg("-un")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|u| !u.is_empty())
        });
        let Some(user) = user else { return false };
        Path::new("/var/lib/systemd/linger").join(user).exists()
    }

    pub fn uninstall() -> Result<(), ServiceError> {
        let unit = unit_path()?;
        // Best-effort: non-zero when the service isn't loaded.
        if let Err(e) = run_tool(
            "systemctl",
            "disable --now",
            &["--user", "disable", "--now", "p2claw-agent.service"],
        ) {
            warn!(error = %e, "systemctl disable --now failed (continuing to remove unit)");
        }
        if unit.exists() {
            fs::remove_file(&unit).map_err(|e| ServiceError::Io {
                path: unit.display().to_string(),
                source: e,
            })?;
            println!("removed {}", unit.display());
        } else {
            println!("(no unit at {})", unit.display());
        }
        let _ = run_tool("systemctl", "daemon-reload", &["--user", "daemon-reload"]);
        Ok(())
    }

    pub fn status() -> Result<(), ServiceError> {
        let st = Command::new("systemctl")
            .args(["--user", "status", "p2claw-agent.service", "--no-pager"])
            .status()
            .map_err(|e| ServiceError::ToolFailed {
                tool: "systemctl",
                action: "status",
                status: format!("spawn failed: {e}"),
                stderr: String::new(),
            })?;
        if !st.success() {
            let unit = unit_path()?;
            if !unit.exists() {
                println!(
                    "p2claw service is not installed (no unit at {})",
                    unit.display()
                );
            }
        }
        Ok(())
    }

    /// Compare the on-disk systemd unit against the current
    /// `render_unit`; rewrite + reload when it differs.
    pub fn check_drift(rewrite: bool) -> Result<DriftReport, ServiceError> {
        let unit = unit_path()?;
        let bin = resolve_bin_path(None)?;
        check_drift_at(&unit, &bin, rewrite, /* reload */ true)
    }

    /// `P2CLAW_RELEASE_REPO` value from an installed unit, if any.
    fn unit_release_repo(unit: &str) -> Option<String> {
        let prefix = format!("Environment={}=", crate::auto_upgrade::RELEASE_REPO_ENV);
        unit.lines()
            .find_map(|l| l.strip_prefix(prefix.as_str()))
            .map(str::trim)
            .filter(|v| is_valid_repo_slug(v))
            .map(str::to_string)
    }

    /// Pure inner: explicit unit + bin paths and a `reload` toggle
    /// so tests can exercise the comparison without poking
    /// process-wide `XDG_CONFIG_HOME` / `current_exe()` or invoking
    /// `systemctl`.
    pub(super) fn check_drift_at(
        unit: &Path,
        bin: &Path,
        rewrite: bool,
        reload: bool,
    ) -> Result<DriftReport, ServiceError> {
        let have = match fs::read_to_string(unit) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(DriftReport {
                    path: unit.to_path_buf(),
                    state: DriftState::NotInstalled,
                });
            }
            Err(e) => {
                return Err(ServiceError::Io {
                    path: unit.display().to_string(),
                    source: e,
                });
            }
        };
        // Always expect the publish-only env line, and carry over any
        // release-repo override already in the unit so a rewrite
        // doesn't drop it.
        let release_repo = unit_release_repo(&have);
        let want = render_unit(bin, &service_env(true, release_repo.as_deref()));
        if have == want {
            return Ok(DriftReport {
                path: unit.to_path_buf(),
                state: DriftState::Clean,
            });
        }
        if !rewrite {
            return Ok(DriftReport {
                path: unit.to_path_buf(),
                state: DriftState::Drifted { rewrote: false },
            });
        }
        write_atomic(unit, &want, 0o644)?;
        if reload {
            let _ = run_tool("systemctl", "daemon-reload", &["--user", "daemon-reload"]);
        }
        Ok(DriftReport {
            path: unit.to_path_buf(),
            state: DriftState::Drifted { rewrote: true },
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fake_bin(dir: &Path) -> PathBuf {
            let p = dir.join("p2claw-fake-bin");
            std::fs::write(&p, b"fake").unwrap();
            p
        }

        #[test]
        fn drift_check_returns_not_installed_for_missing_file() {
            let dir = tempfile::tempdir().unwrap();
            let unit = dir.path().join("absent.service");
            let bin = fake_bin(dir.path());
            let report = check_drift_at(
                &unit, &bin, /* rewrite */ false, /* reload */ false,
            )
            .unwrap();
            assert!(matches!(report.state, DriftState::NotInstalled));
        }

        #[test]
        fn drift_check_returns_clean_for_byte_stable_unit() {
            let dir = tempfile::tempdir().unwrap();
            let unit = dir.path().join("p2claw-agent.service");
            let bin = fake_bin(dir.path());
            // Pre-write the same render the check expects.
            std::fs::write(
                &unit,
                render_unit(&bin, &[("P2CLAW_AGENT_DISABLE_MAGICDNS", "true")]),
            )
            .unwrap();
            let report = check_drift_at(
                &unit, &bin, /* rewrite */ false, /* reload */ false,
            )
            .unwrap();
            assert!(matches!(report.state, DriftState::Clean));
        }

        #[test]
        fn drift_check_returns_drifted_without_rewriting_when_rewrite_false() {
            let dir = tempfile::tempdir().unwrap();
            let unit = dir.path().join("p2claw-agent.service");
            let bin = fake_bin(dir.path());
            // Stale unit — looks like an old install (no LimitNOFILE).
            let stale = "[Unit]\nDescription=p2claw agent\n";
            std::fs::write(&unit, stale).unwrap();
            let report = check_drift_at(
                &unit, &bin, /* rewrite */ false, /* reload */ false,
            )
            .unwrap();
            assert!(
                matches!(report.state, DriftState::Drifted { rewrote: false }),
                "{:?}",
                report.state
            );
            // On-disk content unchanged because rewrite=false.
            assert_eq!(std::fs::read_to_string(&unit).unwrap(), stale);
        }

        #[test]
        fn drift_check_rewrites_stale_unit_when_rewrite_true() {
            let dir = tempfile::tempdir().unwrap();
            let unit = dir.path().join("p2claw-agent.service");
            let bin = fake_bin(dir.path());
            // Stale unit shape an old install would have left behind,
            // before `LimitNOFILE` was added to `render_unit`.
            let stale = "[Unit]\nDescription=p2claw agent\n";
            std::fs::write(&unit, stale).unwrap();
            let report = check_drift_at(
                &unit, &bin, /* rewrite */ true, /* reload */ false,
            )
            .unwrap();
            assert!(
                matches!(report.state, DriftState::Drifted { rewrote: true }),
                "{:?}",
                report.state
            );
            // On-disk content now matches current render.
            let have = std::fs::read_to_string(&unit).unwrap();
            assert_eq!(
                have,
                render_unit(&bin, &[("P2CLAW_AGENT_DISABLE_MAGICDNS", "true")])
            );
            assert!(
                have.contains("LimitNOFILE=65536"),
                "post-rewrite unit must include the FD-limit bump"
            );
        }

        #[test]
        fn drift_rewrite_keeps_release_repo_override() {
            let dir = tempfile::tempdir().unwrap();
            let unit = dir.path().join("p2claw-agent.service");
            let bin = fake_bin(dir.path());
            // Installed with an override, then the binary moved.
            let installed = render_unit(
                Path::new("/old/p2claw"),
                &service_env(true, Some("acme/p2claw-fork")),
            );
            std::fs::write(&unit, installed).unwrap();
            let report = check_drift_at(
                &unit, &bin, /* rewrite */ true, /* reload */ false,
            )
            .unwrap();
            assert!(matches!(
                report.state,
                DriftState::Drifted { rewrote: true }
            ));
            let have = std::fs::read_to_string(&unit).unwrap();
            assert!(have.contains("Environment=P2CLAW_RELEASE_REPO=acme/p2claw-fork"));
            assert!(have.contains(&format!("ExecStart={} run", bin.display())));

            // A second check is clean: the override isn't itself drift.
            let report = check_drift_at(&unit, &bin, false, false).unwrap();
            assert!(
                matches!(report.state, DriftState::Clean),
                "{:?}",
                report.state
            );
        }

        #[test]
        fn unit_release_repo_ignores_malformed_values() {
            assert_eq!(
                unit_release_repo("Environment=P2CLAW_RELEASE_REPO=acme/fork\n"),
                Some("acme/fork".to_string())
            );
            assert_eq!(
                unit_release_repo("Environment=P2CLAW_RELEASE_REPO=not a slug\n"),
                None
            );
            assert_eq!(
                unit_release_repo("Environment=P2CLAW_AGENT_DISABLE_MAGICDNS=true\n"),
                None
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// non-macOS / non-Linux — explicit unsupported
// ─────────────────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::*;

    pub fn install(_opts: InstallOpts) -> Result<(), ServiceError> {
        Err(ServiceError::UnsupportedPlatform)
    }
    pub fn uninstall() -> Result<(), ServiceError> {
        Err(ServiceError::UnsupportedPlatform)
    }
    pub fn status() -> Result<(), ServiceError> {
        Err(ServiceError::UnsupportedPlatform)
    }
    pub fn check_drift(_rewrite: bool) -> Result<DriftReport, ServiceError> {
        Err(ServiceError::UnsupportedPlatform)
    }
}

// ─────────────────────────────────────────────────────────────────────
// Public surface — what main.rs dispatches to
// ─────────────────────────────────────────────────────────────────────

pub fn install(opts: InstallOpts) -> Result<(), ServiceError> {
    platform::install(opts)
}
pub fn uninstall() -> Result<(), ServiceError> {
    platform::uninstall()
}
pub fn status() -> Result<(), ServiceError> {
    platform::status()
}

/// Re-render the platform's service-config and compare against
/// disk; with `rewrite=true`, write the new render and reload the
/// supervisor when they differ. Auto-upgrade calls this with
/// `rewrite=true`; `service-config --check` uses `false`.
///
/// Binary-path comparison matches `install`'s logic
/// (`current_exe`-canonicalised), so a stock install renders
/// identically. A moved binary registers as drift; the rewrite
/// fixes it.
pub fn check_drift(rewrite: bool) -> Result<DriftReport, ServiceError> {
    platform::check_drift(rewrite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_slug_validation() {
        assert!(is_valid_repo_slug("phact/p2claw-agent"));
        assert!(is_valid_repo_slug("acme.io/fork_1"));
        for bad in [
            "", "noslash", "/repo", "owner/", "a/b/c", "a b/c", "a/<x>", "a/b\nX=1",
        ] {
            assert!(!is_valid_repo_slug(bad), "{bad:?}");
        }
    }

    #[test]
    fn plist_release_repo_reads_the_env_entry() {
        let plist = "<key>P2CLAW_AGENT_DISABLE_MAGICDNS</key>\n<string>true</string>\n\
                     <key>P2CLAW_RELEASE_REPO</key>\n        <string>acme/fork</string>";
        assert_eq!(plist_release_repo(plist), Some("acme/fork".to_string()));
        assert_eq!(
            plist_release_repo("<key>PATH</key><string>/usr/bin</string>"),
            None
        );
        assert_eq!(
            plist_release_repo("<key>P2CLAW_RELEASE_REPO</key><string>bad value</string>"),
            None
        );
    }

    #[test]
    fn service_env_orders_and_omits_entries() {
        assert!(service_env(false, None).is_empty());
        assert_eq!(
            service_env(true, Some("acme/fork")),
            vec![
                ("P2CLAW_AGENT_DISABLE_MAGICDNS", "true"),
                ("P2CLAW_RELEASE_REPO", "acme/fork"),
            ]
        );
    }
}
