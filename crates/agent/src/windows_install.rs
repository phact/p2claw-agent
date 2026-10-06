//! Windows system-scope install integration.
//!
//! Mirror of `macos_install` and `linux_install` for Windows.
//! Same `--system` flag, same `install_system / uninstall_system`
//! shape, Windows-flavored mechanisms.
//!
//! ## Why no `#![cfg(target_os = "windows")]` on the module
//!
//! Unlike `macos_install` / `linux_install`, this module compiles
//! on every platform so the **pure render-function tests run on
//! Linux dev boxes**. Only the
//! `is_admin` runtime check is `#[cfg]`-gated; everything else
//! (render functions, path constants, the install / uninstall
//! shells-out-to-PowerShell logic) compiles cross-platform. On
//! non-Windows the runtime functions error helpfully via
//! [`InstallError::WrongPlatform`] before invoking any Windows-
//! only command.
//!
//! ## What it does (Windows operator runs as admin)
//!
//! 1. **NRPT rule** for DNS routing.
//!    `Add-DnsClientNrptRule -Namespace ".<parent_domain>"
//!    -NameServers "127.0.0.1"`. NRPT (Name Resolution Policy
//!    Table) is Windows's per-namespace DNS routing facility —
//!    tells the resolver "for queries matching this namespace,
//!    use the listed DNS servers exclusively." Caveat: NRPT
//!    rules do NOT accept a port specifier; queries always go to
//!    UDP/TCP **port 53** at the configured nameserver. So on
//!    Windows the agent's DNS resolver MUST bind 127.0.0.1:53
//!    (not the 5454 default macOS/Linux use). Windows has no
//!    sub-1024-port-privilege restriction; binding 53 from a
//!    non-elevated service works. The Windows Service
//!    definition sets `P2CLAW_DNS_PORT=53` in the environment;
//!    the agent's DNS-resolver config reads that env var at
//!    startup and binds the requested port.
//! 2. **Windows Service** registration. `New-Service -Name
//!    p2claw-agent -BinaryPathName "<bin> run" -DisplayName
//!    "p2claw agent" -StartupType Automatic`. Runs as
//!    LocalSystem by default — we leave that as the current
//!    posture (matches the macOS root-default). Once a target-user
//!    resolution story lands, the New-Service can add `-Credential`
//!    to drop privileges.
//! 3. **CA root install** into the System Root store.
//!    `Import-Certificate -FilePath <ca.crt> -CertStoreLocation
//!    Cert:\LocalMachine\Root`. Requires admin elevation; the
//!    operator running `p2claw service install --system` from an
//!    elevated PowerShell sees no extra prompt (the
//!    elevation already covered it).
//! 4. **443 conflict pre-flight**. Same `TcpListener::bind`
//!    probe as the other platforms; `netstat -ano | findstr
//!    :443` for owner attribution if the bind fails.
//! 5. **Symmetric uninstall** removes each piece (Service,
//!    NRPT rule, CA cert).

// Module compiles cross-platform so the pure render-function tests
// run on Linux dev boxes. On non-Windows hosts the install/uninstall
// runtime paths are unreachable from `main` (the dispatch in
// `cmd_install_system` / `cmd_uninstall_system` is `cfg`-gated to
// `target_os = "windows"`), so most of this module's items show as
// "never used" to the linter on Linux. The blanket `dead_code` allow
// silences that without per-item annotation noise. Tests + Windows
// builds use everything; this allow only takes effect on the
// non-target platforms.
#![allow(dead_code)]

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;
use tracing::{info, warn};

/// Windows Service name. Used by `sc.exe` / PowerShell `Get-Service`
/// to find the agent post-install. Stable across install /
/// uninstall.
pub const SERVICE_NAME: &str = "p2claw-agent";

/// DNS port the agent's `dns_resolver` MUST bind to on Windows.
/// NRPT routes queries to port 53 unconditionally (no port spec
/// in `Add-DnsClientNrptRule`); Windows has no privileged-port
/// restriction, so a non-elevated service can bind 53.
///
/// Important: the agent's main defaults to
/// [`DEFAULT_BIND`-via-`DnsResolverConfig`] which is port 5454.
/// Windows installs override this by setting `P2CLAW_DNS_PORT=53`
/// in the Service definition's environment; the agent's startup
/// resolves the env var into the bind port for `DnsResolverConfig`.
pub const DNS_PORT_WINDOWS: u16 = 53;

/// Windows path to the LocalMachine Root certificate store. Per
/// `Get-Help Import-Certificate`. Standard place for a
/// system-wide trusted root.
pub const CERT_STORE_LOCATION: &str = "Cert:\\LocalMachine\\Root";

/// Common Name on the local CA root cert (set in
/// `local_ca::load_or_generate`). Used by uninstall to find +
/// remove the cert from the store via `Get-ChildItem ... |
/// Where-Object Subject -Like "*<CN>*" | Remove-Item`.
pub const CA_ROOT_CN: &str = "p2claw local CA";

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("`p2claw service install --system` requires Windows for this dispatch arm; you're running on a non-Windows host")]
    WrongPlatform,
    #[error(
        "Windows system-scope install requires admin elevation; re-run from an elevated PowerShell"
    )]
    NotAdmin,
    #[error("port 443 is already bound on 0.0.0.0 or 127.0.0.1: {detail}")]
    PortConflict { detail: String },
    #[error("could not determine the running binary's path: {0}")]
    NoCurrentExe(#[source] std::io::Error),
    #[error("`{bin}` is not present at `{path}`")]
    BinNotFound { bin: &'static str, path: String },
    // `read_parent_domain_from_state` falls back to
    // `crate::DEFAULT_PARENT_DOMAIN` (canonical `p2claw.com`,
    // build-time overridable via `P2CLAW_DEFAULT_PARENT_DOMAIN`)
    // when neither the CLI flag nor `agent.state` provides one.
    // Fresh boxes that haven't yet registered don't see an
    // install-time nag.
    #[error("io on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("`{tool} {action}` exited with status {status}: {stderr}")]
    ToolFailed {
        tool: &'static str,
        action: &'static str,
        status: String,
        stderr: String,
    },
    #[error("could not load/generate local CA root: {0}")]
    LocalCa(String),
}

pub struct InstallSystemOpts {
    pub bin_path: Option<PathBuf>,
    pub parent_domain: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub no_start: bool,
    pub dry_run: bool,
}

pub struct UninstallSystemOpts {
    pub parent_domain: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub dry_run: bool,
}

pub fn install_system(opts: InstallSystemOpts) -> Result<(), InstallError> {
    if !cfg!(target_os = "windows") && !opts.dry_run {
        return Err(InstallError::WrongPlatform);
    }
    if !is_admin() && !opts.dry_run {
        return Err(InstallError::NotAdmin);
    }

    // 1. Resolve the binary path the Service should run.
    let bin = resolve_bin(opts.bin_path.clone())?;
    if !bin.exists() {
        return Err(InstallError::BinNotFound {
            bin: "p2claw",
            path: bin.display().to_string(),
        });
    }

    // 2. Resolve data_dir + parent_domain.
    let data_dir = opts
        .data_dir
        .clone()
        .unwrap_or_else(default_windows_data_dir);
    let parent_domain = opts
        .parent_domain
        .clone()
        .unwrap_or_else(|| read_parent_domain_from_state(&data_dir));

    // 3. Pre-flight: 443 isn't already bound elsewhere.
    if let Err(detail) = check_443_free() {
        return Err(InstallError::PortConflict { detail });
    }

    // 4. Mint local CA root if it's missing on disk.
    let ca_cert_path = data_dir.join("local_ca.crt");
    if !ca_cert_path.exists() {
        info!(
            data_dir = %data_dir.display(),
            "windows_install: minting local CA root (load_or_generate)"
        );
        if !opts.dry_run {
            std::fs::create_dir_all(&data_dir).map_err(|e| InstallError::Io {
                path: data_dir.display().to_string(),
                source: e,
            })?;
            p2claw_agent::local_ca::LocalCa::load_or_generate(&data_dir)
                .map_err(|e| InstallError::LocalCa(e.to_string()))?;
        }
    }

    // 5. Install CA root into the LocalMachine Root store.
    if !opts.dry_run {
        let ps = render_ca_install_powershell(&ca_cert_path);
        run_powershell("Import-Certificate", &ps)?;
    }
    print_action(
        opts.dry_run,
        &format!(
            "installed CA root at {} into {CERT_STORE_LOCATION}",
            ca_cert_path.display()
        ),
    );

    // 6. Add the NRPT rule for DNS routing.
    if !opts.dry_run {
        let ps = render_nrpt_create_powershell(&parent_domain);
        run_powershell("Add-DnsClientNrptRule", &ps)?;
    }
    print_action(
        opts.dry_run,
        &format!(
            "added NRPT rule for .{parent_domain} → 127.0.0.1 (port {DNS_PORT_WINDOWS} required by NRPT)"
        ),
    );

    // 7. Register the Windows Service.
    // Cross-platform parity: same env-capture allow-list as
    // linux_install + macos_install. Without this, the SCM-spawned
    // service gets only the env declared in the registry
    // `Environment` MultiString — NOT the install-time shell's
    // `P2CLAW_*` vars. Service falls through to clap defaults
    // (`coord_domain=coord.p2claw.com`), the same bug-class that
    // hit on Linux.
    let captured: Vec<(&str, Option<String>)> = vec![
        ("P2CLAW_COORD_URL", std::env::var("P2CLAW_COORD_URL").ok()),
        (
            "P2CLAW_COORD_DOMAIN",
            std::env::var("P2CLAW_COORD_DOMAIN").ok(),
        ),
        (
            crate::auto_upgrade::RELEASE_REPO_ENV,
            std::env::var(crate::auto_upgrade::RELEASE_REPO_ENV).ok(),
        ),
    ];
    let extra_env: Vec<(&str, &str)> = captured
        .iter()
        .filter_map(|(k, v)| v.as_deref().map(|s| (*k, s)))
        .collect();
    if !opts.dry_run {
        let ps = render_service_create_powershell(&bin, &data_dir, &extra_env);
        run_powershell("New-Service", &ps)?;
    }
    print_action(
        opts.dry_run,
        &format!(
            "registered Windows Service '{SERVICE_NAME}' running '{} run'",
            bin.display()
        ),
    );
    if !extra_env.is_empty() {
        let keys = extra_env
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(", ");
        print_action(
            opts.dry_run,
            &format!("(captured install-time env into Service registry Environment: {keys})"),
        );
    }

    // 8. Start the Service (unless --no-start).
    if opts.no_start {
        print_action(
            opts.dry_run,
            &format!(
                "(--no-start) skipped Service start. Start later with:\n  \
                 Start-Service -Name {SERVICE_NAME}"
            ),
        );
    } else if !opts.dry_run {
        let ps = format!("Start-Service -Name '{SERVICE_NAME}'");
        run_powershell("Start-Service", &ps)?;
        print_action(
            opts.dry_run,
            &format!("started Windows Service '{SERVICE_NAME}'"),
        );
    }

    print_action(opts.dry_run, "windows_install: done");
    Ok(())
}

pub fn uninstall_system(opts: UninstallSystemOpts) -> Result<(), InstallError> {
    if !cfg!(target_os = "windows") && !opts.dry_run {
        return Err(InstallError::WrongPlatform);
    }
    if !is_admin() && !opts.dry_run {
        return Err(InstallError::NotAdmin);
    }

    let data_dir = opts
        .data_dir
        .clone()
        .unwrap_or_else(default_windows_data_dir);
    // parent_domain resolves via the same chain as install
    // (flag → state file → compile-time default), so uninstall always
    // has a domain to point at. The NRPT-rule removal is best-effort
    // PowerShell — if the install used a different domain, the rule
    // simply doesn't exist and `Remove-DnsClientNrptRule` is a
    // no-op (silent on `-ErrorAction SilentlyContinue`).
    let parent_domain = opts
        .parent_domain
        .clone()
        .unwrap_or_else(|| read_parent_domain_from_state(&data_dir));

    // 1. Stop + remove the Service (best-effort).
    if !opts.dry_run {
        let _ = run_powershell(
            "Stop-Service (uninstall, best-effort)",
            &format!("Stop-Service -Name '{SERVICE_NAME}' -Force -ErrorAction SilentlyContinue"),
        );
        if let Err(e) = run_powershell(
            "Remove-Service",
            &format!("Remove-Service -Name '{SERVICE_NAME}' -ErrorAction SilentlyContinue"),
        ) {
            warn!(error = %e, "windows_install: Remove-Service (uninstall) failed; continuing");
        }
    }
    print_action(
        opts.dry_run,
        &format!("removed Windows Service '{SERVICE_NAME}' (best-effort)"),
    );

    // 2. Remove the NRPT rule. `parent_domain` is always set
    //    (falls back to compile-time default); if the real install
    //    used a different domain, the
    //    `Remove-DnsClientNrptRule -ErrorAction SilentlyContinue`
    //    call is a silent no-op.
    if !opts.dry_run {
        let ps = render_nrpt_remove_powershell(&parent_domain);
        if let Err(e) = run_powershell("Remove-DnsClientNrptRule", &ps) {
            warn!(error = %e, "windows_install: NRPT rule removal failed; continuing");
        }
    }
    print_action(
        opts.dry_run,
        &format!("removed NRPT rule for .{parent_domain} (best-effort)"),
    );

    // 3. Remove the CA root from the LocalMachine Root store.
    if !opts.dry_run {
        let ps = render_ca_remove_powershell();
        if let Err(e) = run_powershell("Remove CA cert", &ps) {
            warn!(error = %e, "windows_install: CA root removal failed; continuing");
        }
    }
    print_action(
        opts.dry_run,
        &format!("removed CA root '{CA_ROOT_CN}' from {CERT_STORE_LOCATION} (best-effort)"),
    );

    // 4. Best-effort DNS cache flush.
    if !opts.dry_run {
        let _ = run_powershell(
            "Clear-DnsClientCache",
            "Clear-DnsClientCache -ErrorAction SilentlyContinue",
        );
    }

    print_action(opts.dry_run, "windows_install: uninstall done");
    Ok(())
}

/// Pre-flight: try binding 443 on both 127.0.0.1 and 0.0.0.0.
/// Same body as the macOS / Linux paths; on Windows we attribute
/// via `netstat -ano | findstr :443` (rather than `lsof` / `ss`).
pub fn check_443_free() -> Result<(), String> {
    match TcpListener::bind("127.0.0.1:443") {
        Ok(l) => drop(l),
        Err(e) => {
            // Best-effort `netstat` attribution. On non-Windows
            // we just surface the bind error without attribution.
            let detail = if cfg!(target_os = "windows") {
                match Command::new("netstat").args(["-ano"]).output() {
                    Ok(out) if out.status.success() => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        let lines_with_443: Vec<&str> =
                            stdout.lines().filter(|l| l.contains(":443")).collect();
                        format!(
                            "127.0.0.1:443 bind failed ({e}); current owner per `netstat -ano | findstr :443`:\n{}",
                            lines_with_443.join("\n")
                        )
                    }
                    _ => format!("127.0.0.1:443 bind failed ({e})"),
                }
            } else {
                format!("127.0.0.1:443 bind failed ({e})")
            };
            return Err(detail);
        }
    }
    match TcpListener::bind("0.0.0.0:443") {
        Ok(l) => drop(l),
        Err(e) => return Err(format!("0.0.0.0:443 bind failed ({e})")),
    }
    Ok(())
}

// ---------- pure render functions (testable cross-platform) ----------

/// PowerShell snippet to add the NRPT rule routing
/// `*.<parent_domain>` queries to `127.0.0.1`. The `.` prefix on
/// `Namespace` per `Get-Help Add-DnsClientNrptRule` makes it a
/// suffix match (any domain ending in `.<parent_domain>` matches).
pub fn render_nrpt_create_powershell(parent_domain: &str) -> String {
    format!(
        "Add-DnsClientNrptRule \
         -Namespace '.{parent_domain}' \
         -NameServers '127.0.0.1' \
         -Comment 'p2claw agent — added by `p2claw service install --system`'"
    )
}

/// PowerShell snippet to remove the NRPT rule on uninstall.
/// Match by Comment so we don't accidentally clobber an
/// operator-added rule that happens to share the namespace.
pub fn render_nrpt_remove_powershell(parent_domain: &str) -> String {
    format!(
        "Get-DnsClientNrptRule | \
         Where-Object {{ $_.Namespace -eq '.{parent_domain}' -and $_.Comment -like '*p2claw agent*' }} | \
         Remove-DnsClientNrptRule -Force"
    )
}

/// PowerShell snippet to register the Windows Service. Uses
/// `New-Service` (PowerShell native) rather than `sc.exe create`
/// (legacy) because `New-Service` is scriptable + integrates
/// with `Get-Service` / `Stop-Service` / etc. without quoting
/// gymnastics.
///
/// `extra_env` carries operator-supplied `P2CLAW_*` env vars
/// captured from the install-time shell (currently
/// `P2CLAW_COORD_URL` / `P2CLAW_COORD_DOMAIN` /
/// `P2CLAW_RELEASE_REPO`). Cross-platform parity with
/// linux_install's `Environment=` lines + macos_install's plist
/// `<EnvironmentVariables>` entries. Same bug-class on
/// Windows: a Service registered without these baked into the
/// registry MultiString gets only the env present at SCM start —
/// NOT what was in the install-time shell — so the agent falls
/// through to clap defaults at runtime, exact same shape as the
/// systemd-Environment bug we hit on Linux.
pub fn render_service_create_powershell(
    bin_path: &Path,
    data_dir: &Path,
    extra_env: &[(&str, &str)],
) -> String {
    // PowerShell single-quoted strings don't need escaping for
    // backslashes; only an embedded `'` in the path would break,
    // and Windows path components don't allow `'` so we're safe.
    let extra_env_entries = extra_env
        .iter()
        .map(|(k, v)| format!(", '{k}={v}'"))
        .collect::<String>();
    format!(
        "New-Service \
         -Name '{SERVICE_NAME}' \
         -BinaryPathName '{bin} run' \
         -DisplayName 'p2claw agent' \
         -Description 'p2claw agent (system-scope install)' \
         -StartupType Automatic; \
         # Set environment via registry — New-Service doesn't expose env in 5.1.\n\
         $envKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\{SERVICE_NAME}'; \
         Set-ItemProperty -Path $envKey -Name 'Environment' \
         -Value @('P2CLAW_AGENT_DATA_DIR={data_dir_str}', 'P2CLAW_DNS_PORT={dns_port}'{extra_env_entries}) \
         -Type MultiString",
        bin = bin_path.display(),
        data_dir_str = data_dir.display(),
        dns_port = DNS_PORT_WINDOWS,
        extra_env_entries = extra_env_entries,
    )
}

/// PowerShell snippet to import the CA root cert into
/// `Cert:\LocalMachine\Root`. `Import-Certificate` requires admin
/// elevation; the operator running install from an elevated
/// shell sees no extra prompt.
pub fn render_ca_install_powershell(ca_path: &Path) -> String {
    format!(
        "Import-Certificate \
         -FilePath '{ca_path}' \
         -CertStoreLocation '{CERT_STORE_LOCATION}'",
        ca_path = ca_path.display(),
    )
}

/// PowerShell snippet to remove the CA cert at uninstall. Match
/// by Subject CN to find the right cert; pipes into Remove-Item.
pub fn render_ca_remove_powershell() -> String {
    format!(
        "Get-ChildItem -Path '{CERT_STORE_LOCATION}' | \
         Where-Object {{ $_.Subject -like '*CN={CA_ROOT_CN}*' }} | \
         Remove-Item -Force"
    )
}

// ---------- helpers ----------

#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    // `net session` returns 0 on success only when the caller is
    // an admin (it queries privileged Server service state). It's
    // the standard way to detect admin from a script without
    // dragging in WinAPI bindings.
    Command::new("net")
        .arg("session")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn is_admin() -> bool {
    // On non-Windows, `is_admin` is meaningless — the runtime
    // platform check (`cfg!(target_os = "windows")`) above
    // catches the wrong-platform case before we ever reach here.
    // Returning false defensively means `install_system` /
    // `uninstall_system` would surface `NotAdmin` if `WrongPlatform`
    // were somehow bypassed.
    false
}

fn default_windows_data_dir() -> PathBuf {
    // Windows convention: per-machine state lives under
    // `%PROGRAMDATA%` (typically `C:\ProgramData`). Distinct
    // from the per-user data dir under `%LOCALAPPDATA%` so a
    // system-scope agent doesn't share identity with a user-
    // scope one. If `%PROGRAMDATA%` is unset (rare), fall back
    // to a hard-coded path.
    let base = std::env::var("PROGRAMDATA").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(base).join("p2claw")
}

fn resolve_bin(override_: Option<PathBuf>) -> Result<PathBuf, InstallError> {
    let p = match override_ {
        Some(p) => p,
        None => std::env::current_exe().map_err(InstallError::NoCurrentExe)?,
    };
    Ok(p.canonicalize().unwrap_or(p))
}

/// Resolve the parent domain to use for install operations,
/// falling back to the compile-time default when neither
/// the CLI flag (caller checks first) nor `agent.state` provides
/// one. Order on disk: state-file value → `crate::DEFAULT_PARENT_DOMAIN`.
///
/// Never errors — fresh boxes that haven't yet registered get
/// the canonical `p2claw.com` (or the build-time
/// `P2CLAW_DEFAULT_PARENT_DOMAIN` override) and `--system`
/// install proceeds without nagging for `--parent-domain`.
fn read_parent_domain_from_state(data_dir: &Path) -> String {
    let state_path = data_dir.join("agent.state");
    let parsed = std::fs::read(&state_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|v| {
            v.get("parent_domain")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        });
    parsed.unwrap_or_else(|| crate::DEFAULT_PARENT_DOMAIN.to_string())
}

/// Run a PowerShell command, returning Ok on exit-0. Wraps the
/// command in `powershell -NoProfile -NonInteractive -Command`
/// to avoid the operator's profile (or interactive prompts)
/// changing behavior. Used for every Windows-only operation;
/// errors out helpfully on non-Windows hosts.
fn run_powershell(action: &'static str, command: &str) -> Result<(), InstallError> {
    if !cfg!(target_os = "windows") {
        return Err(InstallError::WrongPlatform);
    }
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(command)
        .output()
        .map_err(|e| InstallError::ToolFailed {
            tool: "powershell",
            action,
            status: format!("spawn failed: {e}"),
            stderr: String::new(),
        })?;
    if !out.status.success() {
        return Err(InstallError::ToolFailed {
            tool: "powershell",
            action,
            status: out.status.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(())
}

fn print_action(dry_run: bool, line: &str) {
    if dry_run {
        println!("(dry-run) {line}");
    } else {
        println!("{line}");
    }
}

// `Write` is reserved for future PowerShell-script-file emission
// (`render_install_script() -> String` writing a `.ps1` operators
// can audit before running). Today's install runs commands inline.
#[allow(dead_code)]
fn _write_quench(_: &mut dyn Write) {}

#[cfg(test)]
mod tests {
    //! Tests run on **any** target. The pure render functions are
    //! string-builders with no platform-specific dependencies; the
    //! `is_admin` runtime check is `#[cfg]`-gated so it doesn't
    //! interfere. Until this is verified on a real Windows
    //! machine, these tests are the load-bearing correctness
    //! check.
    use super::*;

    #[test]
    fn nrpt_create_powershell_uses_dot_namespace_prefix() {
        let ps = render_nrpt_create_powershell("p2claw.com");
        // Per `Get-Help Add-DnsClientNrptRule`, the leading `.`
        // makes the namespace a suffix match (so any subdomain
        // of p2claw.com is captured). Without the dot it'd only
        // match the literal name `p2claw.com`. Pin the leading
        // dot so a future edit doesn't accidentally drop it.
        assert!(
            ps.contains("-Namespace '.p2claw.com'"),
            "expected leading-dot namespace; got: {ps}"
        );
        assert!(ps.contains("-NameServers '127.0.0.1'"));
        // Comment carries the marker uninstall searches for.
        assert!(ps.contains("p2claw agent"));
    }

    #[test]
    fn nrpt_remove_powershell_filters_by_namespace_and_comment() {
        let ps = render_nrpt_remove_powershell("p2claw.com");
        // Defense-in-depth filter: namespace AND comment match
        // means we won't clobber an operator-added rule that
        // shares the namespace but wasn't put there by us.
        assert!(ps.contains("$_.Namespace -eq '.p2claw.com'"));
        assert!(ps.contains("$_.Comment -like '*p2claw agent*'"));
        assert!(ps.contains("Remove-DnsClientNrptRule -Force"));
    }

    #[test]
    fn service_create_powershell_includes_bin_data_and_dns_port() {
        let bin = PathBuf::from("C:\\Program Files\\p2claw\\p2claw.exe");
        let data = PathBuf::from("C:\\ProgramData\\p2claw");
        let ps = render_service_create_powershell(&bin, &data, &[]);
        // BinaryPathName composes `<bin> run` so the Service
        // wrapper invokes `p2claw run` exactly as the user-scope
        // and system-scope unit + plist do on the other platforms.
        assert!(
            ps.contains("-BinaryPathName 'C:\\Program Files\\p2claw\\p2claw.exe run'"),
            "expected `<bin> run` in BinaryPathName; got: {ps}"
        );
        assert!(ps.contains("-Name 'p2claw-agent'"));
        assert!(ps.contains("-StartupType Automatic"));
        // Environment block — the Service registers env vars that
        // the agent reads at startup. Both keys are load-bearing:
        // `P2CLAW_AGENT_DATA_DIR` redirects state away from the
        // per-user `%LOCALAPPDATA%` path; `P2CLAW_DNS_PORT=53`
        // makes the DNS resolver bind 53 (NRPT requirement —
        // it won't route to a non-53 port).
        assert!(ps.contains("P2CLAW_AGENT_DATA_DIR=C:\\ProgramData\\p2claw"));
        assert!(ps.contains("P2CLAW_DNS_PORT=53"));
    }

    #[test]
    fn service_create_powershell_emits_extra_env_entries() {
        // Cross-platform parity for the env-capture fix.
        // Without these MultiString entries, any
        // `P2CLAW_*` env that was set in the install-time shell
        // is lost when the SCM later starts the Service — agent
        // falls through to clap defaults, exact same bug class
        // we just fixed on Linux + macOS. Pin the serialization
        // shape so a future template edit doesn't accidentally
        // drop the entries from the @() array.
        let bin = PathBuf::from("C:\\Program Files\\p2claw\\p2claw.exe");
        let data = PathBuf::from("C:\\ProgramData\\p2claw");
        let extra = [
            ("P2CLAW_COORD_URL", "http://coord:8081"),
            ("P2CLAW_COORD_DOMAIN", "coord.p2claw.test"),
        ];
        let ps = render_service_create_powershell(&bin, &data, &extra);
        // Extra entries appended onto the existing @() array as
        // additional single-quoted KEY=VALUE elements.
        assert!(
            ps.contains("'P2CLAW_COORD_URL=http://coord:8081'"),
            "missing captured P2CLAW_COORD_URL entry; got:\n{ps}"
        );
        assert!(
            ps.contains("'P2CLAW_COORD_DOMAIN=coord.p2claw.test'"),
            "missing captured P2CLAW_COORD_DOMAIN entry; got:\n{ps}"
        );
        // Always-emitted DATA_DIR + DNS_PORT still present alongside.
        assert!(ps.contains("P2CLAW_AGENT_DATA_DIR=C:\\ProgramData\\p2claw"));
        assert!(ps.contains("P2CLAW_DNS_PORT=53"));
    }

    #[test]
    fn service_create_powershell_with_no_extra_env_omits_extra_entries() {
        let bin = PathBuf::from("C:\\Program Files\\p2claw\\p2claw.exe");
        let data = PathBuf::from("C:\\ProgramData\\p2claw");
        let ps = render_service_create_powershell(&bin, &data, &[]);
        // Only the always-emitted DATA_DIR + DNS_PORT in the
        // MultiString. No P2CLAW_COORD_* / RELEASE_REPO
        // leaked in.
        assert!(ps.contains("P2CLAW_AGENT_DATA_DIR"));
        assert!(ps.contains("P2CLAW_DNS_PORT"));
        assert!(
            !ps.contains("P2CLAW_COORD_URL"),
            "empty extra_env should not emit P2CLAW_COORD_URL; got:\n{ps}"
        );
        assert!(
            !ps.contains("P2CLAW_COORD_DOMAIN"),
            "empty extra_env should not emit P2CLAW_COORD_DOMAIN; got:\n{ps}"
        );
        assert!(
            !ps.contains("P2CLAW_RELEASE_REPO"),
            "empty extra_env should not emit P2CLAW_RELEASE_REPO; got:\n{ps}"
        );
    }

    #[test]
    fn ca_install_powershell_uses_localmachine_root_store() {
        let ca = PathBuf::from("C:\\ProgramData\\p2claw\\local_ca.crt");
        let ps = render_ca_install_powershell(&ca);
        assert!(ps.contains("Import-Certificate"));
        assert!(ps.contains("-FilePath 'C:\\ProgramData\\p2claw\\local_ca.crt'"));
        // LocalMachine\Root is the system-wide trusted-root
        // store; CurrentUser\Root would only trust the cert for
        // the installing user. System-scope install needs the
        // former.
        assert!(ps.contains("'Cert:\\LocalMachine\\Root'"));
    }

    #[test]
    fn ca_remove_powershell_filters_by_subject_cn() {
        let ps = render_ca_remove_powershell();
        // Subject-CN filter ensures we remove only OUR cert, not
        // a CN-collision someone else installed. Pin the CN so a
        // future change to local_ca's subject DN catches the
        // matching uninstall update.
        assert!(ps.contains("$_.Subject -like '*CN=p2claw local CA*'"));
        assert!(ps.contains("Remove-Item -Force"));
        // Operates on the same store the install writes to.
        assert!(ps.contains("'Cert:\\LocalMachine\\Root'"));
    }

    #[test]
    fn read_parent_domain_from_state_extracts_field() {
        let dir = tempfile::tempdir().unwrap();
        let state = serde_json::json!({
            "alias": "test-alias-1234",
            "coord_domain": "coord.p2claw.com",
            "parent_domain": "registered.example",
            "coord_root_pubkey_b64url": "AAAA",
        });
        std::fs::write(
            dir.path().join("agent.state"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();
        // State-file value beats the compile-time default — the
        // box has registered to a custom parent_domain that wins
        // over `crate::DEFAULT_PARENT_DOMAIN`.
        assert_eq!(
            read_parent_domain_from_state(dir.path()),
            "registered.example"
        );
    }

    /// A fresh box that hasn't yet registered (no
    /// `agent.state`) gets the compile-time default instead of an
    /// install-time error nagging the operator for
    /// `--parent-domain`. With `P2CLAW_DEFAULT_PARENT_DOMAIN`
    /// unset, that default is `p2claw.com`.
    #[test]
    fn read_parent_domain_from_state_falls_back_to_default_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_parent_domain_from_state(dir.path()),
            crate::DEFAULT_PARENT_DOMAIN
        );
    }

    #[test]
    fn read_parent_domain_from_state_falls_back_to_default_on_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("agent.state"), b"this is not json").unwrap();
        assert_eq!(
            read_parent_domain_from_state(dir.path()),
            crate::DEFAULT_PARENT_DOMAIN
        );
    }

    #[test]
    fn dns_port_is_53_per_nrpt_constraint() {
        // NRPT (Add-DnsClientNrptRule) doesn't accept a port
        // parameter — queries always go to UDP/TCP 53 at the
        // configured nameserver. So the agent's DNS resolver
        // MUST bind 53 when running under a Windows install,
        // overriding the default 5454 (which the macOS / Linux
        // installs use). Pin the constant so a future edit
        // doesn't accidentally desync from NRPT's reality.
        assert_eq!(DNS_PORT_WINDOWS, 53);
    }

    #[test]
    fn install_system_errors_with_wrong_platform_off_windows() {
        // Skip the test when actually running on Windows — there
        // we'd hit the admin check instead.
        if cfg!(target_os = "windows") {
            return;
        }
        let opts = InstallSystemOpts {
            bin_path: None,
            parent_domain: Some("p2claw.com".to_string()),
            data_dir: None,
            no_start: true,
            dry_run: false,
        };
        let err = install_system(opts).expect_err("non-Windows should refuse");
        assert!(matches!(err, InstallError::WrongPlatform), "{err:?}");
    }
}
