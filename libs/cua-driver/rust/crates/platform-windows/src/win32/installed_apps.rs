//! Windows installed-app enumeration.
//!
//! Two sources:
//!
//! 1. **Start Menu shortcuts**: walks `[CSIDL_COMMON_PROGRAMS]\` and
//!    `[CSIDL_PROGRAMS]\` recursively, resolves each `.lnk` via
//!    `IShellLinkW::GetPath`, and emits one entry per `.exe` target.
//!
//! 2. **UWP / packaged apps**: queries WinRT
//!    `PackageManager::FindPackagesByUserSecurityIdWithPackageTypes("", Main)` for
//!    every `Main` package installed for the current user. Builds the
//!    `shell:appsFolder\{PackageFamilyName}!{AppId}` launch token so
//!    callers can hand it to `launch_app`; `{AppId}` falls back to `App`
//!    when the package manifest does not surface a specific
//!    Application.Id.

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc, OnceLock};
use std::thread;
use std::time::Duration;

use cua_driver_core::single_flight::SingleFlight;
use windows::core::{Interface, PCWSTR};
use windows::Win32::Foundation::MAX_PATH;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED, STGM,
};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

/// Parsed metadata for an installed Windows application.
#[derive(Debug, Clone)]
pub struct InstalledApp {
    /// Display name. For Start-Menu apps: the `.lnk` basename (sans extension).
    /// For UWP apps: the package `DisplayName` from the manifest, falling back
    /// to the package family name when not surfaced.
    pub name: String,
    /// Stable identifier. For Start-Menu apps: the resolved `.exe` path.
    /// For UWP apps: the package family name (e.g. `Microsoft.WindowsCalculator_8wekyb3d8bbwe`).
    pub bundle_id: String,
    /// `"desktop"` for `.lnk`-backed apps, `"uwp"` for packaged apps.
    pub kind: String,
    /// What `launch_app(path=...)` would consume.
    ///   - Desktop: absolute `.exe` path, plus any commandline arguments the
    ///     source `.lnk` carries (e.g.
    ///     `"C:\\Path\\chrome.exe" --profile-directory="Profile 2"`).
    ///     The exe path is quoted when it contains whitespace.
    ///   - UWP: `shell:appsFolder\{PackageFamilyName}!{AppId}` — `{AppId}`
    ///     falls back to `App` when the package manifest doesn't surface a
    ///     specific `Application.Id`.
    pub launch_path: String,
    /// RFC3339 mtime of the launcher (`.lnk` for desktop, package install
    /// path for UWP), when readable; `None` otherwise.
    pub last_used: Option<String>,
    /// Exact timestamp represented by `last_used`. Retained separately so new
    /// callers do not misinterpret launcher/package modification time as
    /// actual user activity.
    pub modified_at: Option<String>,
    /// Executable basenames declared by UWP manifest Application entries.
    /// They correlate ApplicationFrameHost windows with the packaged process
    /// that owns the hosted CoreWindow.
    pub uwp_executables: Vec<String>,
}

/// Aggregate Start-Menu shortcuts and UWP packages into one list.
///
/// Errors from either source are swallowed — the goal is best-effort
/// enumeration, not a guaranteed-complete catalog.
pub fn list_installed_apps() -> Vec<InstalledApp> {
    list_installed_apps_with_status().0
}

/// Aggregate installed applications and report the optional UWP scan status.
pub fn list_installed_apps_with_status() -> (Vec<InstalledApp>, &'static str) {
    let mut out = Vec::new();
    let t0 = std::time::Instant::now();
    let sm = scan_start_menu();
    tracing::debug!(target: "installed_apps", "scan_start_menu: {} entries ({}ms)", sm.len(), t0.elapsed().as_millis());
    out.extend(sm);
    let t1 = std::time::Instant::now();
    let (uwp, uwp_status) = scan_uwp_packages_with_status();
    tracing::debug!(target: "installed_apps", "scan_uwp_packages: {} entries ({}ms)", uwp.len(), t1.elapsed().as_millis());
    out.extend(uwp);

    // Dedupe the exact launch entry. bundle_id alone is the target executable,
    // so using it as the key would collapse different shortcut arguments.
    dedupe_installed_apps(&mut out);
    out.sort_by(app_sort_key);
    (out, uwp_status)
}

fn dedupe_installed_apps(apps: &mut Vec<InstalledApp>) {
    let mut seen = std::collections::HashSet::new();
    apps.retain(|app| {
        seen.insert((
            app.kind.clone(),
            app.bundle_id.clone(),
            app.launch_path.clone(),
        ))
    });
}

fn app_sort_key(a: &InstalledApp, b: &InstalledApp) -> std::cmp::Ordering {
    // Keep recently-used apps near the top when we can infer usage recency.
    // Sort by LastAccessTime, with deterministic name-based fallback.
    match (a.last_used.as_deref(), b.last_used.as_deref()) {
        (Some(ax), Some(bx)) => bx
            .cmp(ax)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    }
}

// ── Start Menu (.lnk) scan ───────────────────────────────────────────────────

fn scan_start_menu() -> Vec<InstalledApp> {
    let mut out = Vec::new();
    let roots = start_menu_roots();
    // COM init for IShellLinkW. Best-effort — if Apartment-threaded init
    // fails (already-initialized as MTA on this thread), the calls below
    // still succeed because IShellLinkW is registered for both apartments.
    let init = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    for root in roots {
        let _ = walk_for_lnks(&root, &mut out);
    }
    if init.is_ok() {
        unsafe { CoUninitialize() };
    }
    out
}

fn start_menu_roots() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = std::env::var("ProgramData") {
        // CSIDL_COMMON_PROGRAMS — machine-wide Start Menu.
        out.push(PathBuf::from(format!(
            "{p}\\Microsoft\\Windows\\Start Menu\\Programs"
        )));
    }
    if let Ok(p) = std::env::var("APPDATA") {
        // CSIDL_PROGRAMS — per-user Start Menu.
        out.push(PathBuf::from(format!(
            "{p}\\Microsoft\\Windows\\Start Menu\\Programs"
        )));
    }
    out
}

fn walk_for_lnks(dir: &Path, sink: &mut Vec<InstalledApp>) -> std::io::Result<()> {
    let entries = std::fs::read_dir(dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let _ = walk_for_lnks(&path, sink);
            continue;
        }
        if path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.eq_ignore_ascii_case("lnk"))
            != Some(true)
        {
            continue;
        }
        if let Some(app) = resolve_lnk(&path) {
            sink.push(app);
        }
    }
    Ok(())
}

/// Resolve a `.lnk` to its target via IShellLinkW. Returns `None` if the
/// target isn't a `.exe` or the resolve failed.
///
/// The `launch_path` is the full commandline — the resolved executable path
/// followed by `IShellLinkW::GetArguments` when non-empty. Many real-world
/// shortcuts encode behavior in their arguments (Chrome profile launchers,
/// per-workspace VS Code shortcuts), so dropping the args would break
/// `launch_app(path=...)` round-trips. The `bundle_id` stays as the exe
/// path alone so the by-basename merge logic in list_apps still works.
fn resolve_lnk(lnk_path: &Path) -> Option<InstalledApp> {
    let (target, args) = unsafe { read_lnk_target(lnk_path) }.ok()?;
    if !target.to_ascii_lowercase().ends_with(".exe") {
        return None;
    }
    let name = lnk_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_owned();
    if name.is_empty() {
        return None;
    }

    let last_used = std::fs::metadata(lnk_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| cua_driver_core::timestamp::unix_secs_to_rfc3339(d.as_secs() as i64));

    let launch_path = if args.trim().is_empty() {
        target.clone()
    } else {
        // Quote the exe path if it contains whitespace so a shell-style
        // parse round-trips correctly. Arguments are passed through as
        // received from the shortcut — Windows preserves their own quoting.
        let exe_token = if target.contains(' ') {
            format!("\"{target}\"")
        } else {
            target.clone()
        };
        format!("{exe_token} {}", args.trim())
    };

    Some(InstalledApp {
        name,
        bundle_id: target,
        kind: "desktop".to_owned(),
        launch_path,
        modified_at: last_used.clone(),
        last_used,
        uwp_executables: Vec::new(),
    })
}

/// COM-call into IShellLinkW / IPersistFile to read the target `.exe` path and
/// any commandline arguments encoded in the shortcut. Returns `(target, args)`
/// — `args` is the empty string when the shortcut carries no arguments.
unsafe fn read_lnk_target(lnk_path: &Path) -> windows::core::Result<(String, String)> {
    let shell_link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
    let persist: IPersistFile = shell_link.cast()?;

    let wide_path = to_wide_nul(lnk_path.to_string_lossy().as_ref());
    persist.Load(PCWSTR(wide_path.as_ptr()), STGM(0))?;

    let mut path_buf = vec![0u16; MAX_PATH as usize + 1];
    // Raw shortcut paths can contain %windir%; launch_path consumers need the resolved target.
    shell_link.GetPath(&mut path_buf, std::ptr::null_mut(), 0)?;

    // INFOTIPSIZE (1024) is the documented upper bound for the LNK
    // arguments field; allocate one extra slot for the NUL terminator.
    let mut args_buf = vec![0u16; 1025];
    // GetArguments succeeds with an empty string when no args are set —
    // we don't need to special-case that case.
    let args_res = shell_link.GetArguments(&mut args_buf);
    let args = if args_res.is_ok() {
        decode_wstr(&args_buf)
    } else {
        String::new()
    };

    Ok((decode_wstr(&path_buf), args))
}

fn to_wide_nul(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn decode_wstr(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

// ── UWP / packaged-app enumeration via WinRT PackageManager ──────────────────

const UWP_SCAN_TIMEOUT: Duration = Duration::from_secs(4);
const UWP_SCAN_RECOVERY_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UwpScanDeadlineError {
    Timeout,
    Busy,
    Unavailable,
}

/// Process-wide bound for the optional WinRT package scan.
///
/// PackageManager calls cannot be safely cancelled after they enter WinRT. A
/// timed-out worker therefore retains this gate until it actually returns;
/// retries fail fast instead of accumulating one blocked thread per
/// `list_apps` call. Once a late worker returns, a short cooldown prevents a
/// hot retry loop against a broken package repository or token context.
fn uwp_scan_single_flight() -> &'static Arc<SingleFlight> {
    static GATE: OnceLock<Arc<SingleFlight>> = OnceLock::new();
    GATE.get_or_init(|| Arc::new(SingleFlight::new(UWP_SCAN_RECOVERY_COOLDOWN)))
}

fn run_uwp_scan<T, F>(
    gate: &Arc<SingleFlight>,
    timeout: Duration,
    f: F,
) -> Result<T, UwpScanDeadlineError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let Some(permit) = gate.try_acquire() else {
        return Err(UwpScanDeadlineError::Busy);
    };
    let timed_out = permit.timeout_flag();

    let (tx, rx) = mpsc::channel();
    let spawn = thread::Builder::new()
        .name("cua-uwp-package-scan".to_owned())
        .spawn(move || {
            let _ = tx.send(f());
            if permit.timed_out() {
                tracing::warn!(
                    target: "installed_apps",
                    "scan_uwp_packages: timed-out WinRT query returned; cooling down before retry"
                );
            }
            // Dropping the permit arms the cooldown after a timeout and
            // reopens the gate.
            drop(permit);
        });

    if let Err(error) = spawn {
        // The unspawned closure, and with it the permit, is already dropped,
        // which reopened the gate.
        tracing::warn!(
            target: "installed_apps",
            "scan_uwp_packages: failed to start bounded WinRT worker: {error}"
        );
        return Err(UwpScanDeadlineError::Unavailable);
    }

    match rx.recv_timeout(timeout) {
        Ok(result) => Ok(result),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            timed_out.store(true, Ordering::Release);
            // Arm the cooldown here as well as when the permit drops. The
            // worker can return in the narrow interval between `recv_timeout`
            // expiring and observing `timed_out`; recording it on the caller
            // side ensures that race cannot immediately launch another package
            // query.
            gate.arm_cooldown();
            tracing::warn!(
                target: "installed_apps",
                "scan_uwp_packages: current-user WinRT query exceeded {}ms; returning Start Menu apps without UWP results. No additional package worker will start until this query returns",
                timeout.as_millis()
            );
            Err(UwpScanDeadlineError::Timeout)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            tracing::warn!(
                target: "installed_apps",
                "scan_uwp_packages: bounded WinRT worker exited without a result"
            );
            Err(UwpScanDeadlineError::Unavailable)
        }
    }
}

fn scan_uwp_packages_with_status() -> (Vec<InstalledApp>, &'static str) {
    match run_uwp_scan(
        uwp_scan_single_flight(),
        UWP_SCAN_TIMEOUT,
        scan_uwp_packages_unbounded,
    ) {
        Ok(Ok(packages)) => (packages, "complete"),
        Ok(Err(error)) => {
            tracing::warn!(target: "installed_apps", "scan_uwp_packages: WinRT error: {error}");
            (Vec::new(), "unavailable")
        }
        Err(UwpScanDeadlineError::Busy) => {
            tracing::debug!(
                target: "installed_apps",
                "scan_uwp_packages: skipped while a prior WinRT query is in flight or cooling down"
            );
            (Vec::new(), "busy")
        }
        Err(UwpScanDeadlineError::Timeout) => (Vec::new(), "timed_out"),
        Err(UwpScanDeadlineError::Unavailable) => (Vec::new(), "unavailable"),
    }
}

fn scan_uwp_packages_unbounded() -> Result<Vec<InstalledApp>, String> {
    // Wrapped in catch_unwind because the WinRT activation path can panic on
    // very old Windows builds (pre-1809) that lack PackageManager altogether.
    let result = std::panic::catch_unwind(|| -> windows::core::Result<Vec<InstalledApp>> {
        use windows::ApplicationModel::Package;
        use windows::Management::Deployment::{PackageManager, PackageTypes};

        let pm = PackageManager::new()?;
        // The no-user overload queries the machine package repository and can
        // require privileges a normal per-user daemon does not have. Microsoft
        // documents an empty SID here as the current user, which matches both
        // list_apps semantics and Get-AppxPackage's default scope.
        let packages = pm.FindPackagesByUserSecurityIdWithPackageTypes(
            &windows::core::HSTRING::new(),
            PackageTypes::Main,
        )?;

        let mut out = Vec::new();
        for pkg in packages {
            // `pkg: Package` — annotate locally to satisfy the type
            // inference paths through `id.FamilyName()` and friends.
            let pkg: Package = pkg;
            let id = match pkg.Id() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let family_name = match id.FamilyName() {
                Ok(h) => h.to_string(),
                Err(_) => continue,
            };
            if family_name.is_empty() {
                continue;
            }
            if looks_like_system_component_family(&family_name) {
                continue;
            }

            // (Frameworks: Visual C++ runtime, .NET shared assemblies,
            // language packs etc.) — we'd ideally filter via
            // `pkg.IsFramework()`, but that WinRT call has been observed
            // to hang in Session 0 on some Win11 SKUs. Skipping for now;
            // the opaque-family-name filter below catches most of the
            // noise these would have contributed.

            let raw_display = pkg.DisplayName().ok().map(|h| h.to_string());
            let display = normalize_uwp_display_name(raw_display, &pkg, &family_name);

            // Filter out packages whose display name ended up identical
            // to the family name (e.g. `1527c705-839a-4832-...!App` for
            // an opaque system Component without a `<Properties><DisplayName>`
            // entry in its manifest). These show up as line noise in
            // list_apps and are typically unactivatable system pieces
            // the agent should never invoke. Real user-facing apps
            // almost always have a meaningful DisplayName.
            if display == family_name && looks_like_opaque_system_family(&family_name) {
                continue;
            }

            let last_used = read_install_mtime(&pkg);
            let manifest_applications = read_uwp_application_entries(&pkg);
            let mut applications = Vec::new();
            if let Ok(entries) = pkg.GetAppListEntries() {
                for entry in entries {
                    let Ok(aumid) = entry.AppUserModelId().map(|value| value.to_string()) else {
                        continue;
                    };
                    if aumid.is_empty() {
                        continue;
                    }
                    let application_id = aumid.split_once('!').map(|(_, id)| id).unwrap_or("App");
                    let executable = manifest_applications
                        .iter()
                        .find(|(id, _)| id.eq_ignore_ascii_case(application_id))
                        .map(|(_, executable)| executable.clone())
                        .unwrap_or_default();
                    let entry_display = entry
                        .DisplayInfo()
                        .ok()
                        .and_then(|info| info.DisplayName().ok())
                        .map(|value| value.to_string())
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| display.clone());
                    applications.push((entry_display, aumid, executable));
                }
            }
            if applications.is_empty() {
                if let Some((application_id, executable)) = manifest_applications.first() {
                    applications.push((
                        display.clone(),
                        format!("{family_name}!{application_id}"),
                        executable.clone(),
                    ));
                } else {
                    applications.push((
                        display.clone(),
                        format!("{family_name}!App"),
                        String::new(),
                    ));
                }
            }
            let primary = select_primary_uwp_application(&applications);
            let (entry_display, aumid, _) = applications[primary].clone();
            let mut uwp_executables = applications
                .iter()
                .filter_map(|(_, _, executable)| {
                    let basename = std::path::Path::new(executable)
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or(executable)
                        .to_ascii_lowercase();
                    (!basename.is_empty()).then_some(basename)
                })
                .collect::<Vec<_>>();
            uwp_executables.sort();
            uwp_executables.dedup();
            out.push(InstalledApp {
                name: entry_display,
                bundle_id: family_name.clone(),
                kind: "uwp".to_owned(),
                launch_path: format!("shell:appsFolder\\{aumid}"),
                modified_at: last_used.clone(),
                last_used: last_used.clone(),
                uwp_executables,
            });
        }
        Ok(out)
    });

    match result {
        Ok(Ok(v)) => {
            // #1636: when scan_uwp_packages returns 0 packages, log a warning
            // so users hitting the "Calculator isn't in list_apps" gap see a
            // hint immediately instead of silently empty output. The Windows
            // packaging stack reliably has Microsoft.WindowsCalculator and
            // similar OS-bundled UWP apps registered for every user that's
            // logged in interactively at least once, so a zero result usually
            // means PackageManager.FindPackagesByUserSecurityIdWithPackageTypes failed
            // silently (rare COM hiccup, locale issue, etc.) rather than a
            // truly empty package set. Surfacing this in tracing lets users
            // and triage agents (#1636) diagnose without an extra Win32 round-
            // trip. Set RUST_LOG=installed_apps=warn to see the message.
            if v.is_empty() {
                tracing::warn!(
                    target: "installed_apps",
                    "scan_uwp_packages: WinRT PackageManager.FindPackagesByUserSecurityIdWithPackageTypes(current user, Main) \
                     returned 0 UWP packages. Expected at least the OS-bundled apps \
                     (Calculator, modern Settings, Photos, ...). See #1636 — usually means \
                     either a COM activation hiccup or a per-user package context the daemon \
                     can't see. Cross-check with PowerShell `Get-AppxPackage`."
                );
            }
            Ok(v)
        }
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("WinRT package scan panicked (very old Windows?)".to_owned()),
    }
}

/// Best-effort parse of every launchable Application entry in AppxManifest.xml.
fn read_uwp_application_entries(pkg: &windows::ApplicationModel::Package) -> Vec<(String, String)> {
    let Ok(base) = pkg.InstalledPath().map(|value| value.to_string()) else {
        return Vec::new();
    };
    if base.is_empty() {
        return Vec::new();
    }
    let manifest = std::path::Path::new(&base).join("AppxManifest.xml");
    let Ok(xml) = std::fs::read_to_string(manifest) else {
        return Vec::new();
    };
    parse_uwp_application_entries(&xml)
}

fn parse_uwp_application_entries(xml: &str) -> Vec<(String, String)> {
    let mut entries = Vec::new();
    let mut remaining = xml;
    while let Some(start) = remaining.find("<Application") {
        let tail = &remaining[start..];
        let Some(end) = tail.find('>') else {
            break;
        };
        let tag = &tail[..end];
        if let Some(app_id) = xml_attribute(tag, "Id") {
            let executable = xml_attribute(tag, "Executable").unwrap_or_default();
            entries.push((app_id, executable));
        }
        remaining = &tail[end + 1..];
    }
    entries
}

fn xml_attribute(tag: &str, name: &str) -> Option<String> {
    let marker = format!("{name}=\"");
    let start = tag.find(&marker)? + marker.len();
    let rest = &tag[start..];
    let end = rest.find('"')?;
    let value = rest[..end].trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn select_primary_uwp_application(entries: &[(String, String, String)]) -> usize {
    if let Some(index) = entries
        .iter()
        .position(|(_, aumid, _)| uwp_application_id(aumid).eq_ignore_ascii_case("App"))
    {
        return index;
    }
    entries
        .iter()
        .position(|(_, aumid, _)| {
            !looks_like_internal_uwp_application_id(uwp_application_id(aumid))
        })
        .unwrap_or(0)
}

fn uwp_application_id(aumid: &str) -> &str {
    aumid.split_once('!').map(|(_, id)| id).unwrap_or("App")
}

fn looks_like_internal_uwp_application_id(application_id: &str) -> bool {
    let value = application_id.to_ascii_lowercase();
    value.starts_with("global.")
        || [
            "packagemetadata",
            "mcpserver",
            "protocolshim",
            "redirector",
            "comserver",
            "commandrunner",
            "nativehost",
            "plugin",
            "extension",
            "service",
            ".cdb",
            ".kd",
            ".ntsd",
            ".dbgsrv",
            "mcpproxy",
        ]
        .iter()
        .any(|marker| value.contains(marker))
}

fn looks_like_system_component_family(family_name: &str) -> bool {
    let value = family_name.to_ascii_lowercase();
    value.starts_with("microsoftwindows.")
        || value.starts_with("microsoft.windows.shellexperiencehost_")
        || value.starts_with("microsoft.windows.peopleexperiencehost_")
        || value.starts_with("microsoft.windows.cloudexperiencehost_")
        || value.starts_with("microsoft.windows.startmenuexperiencehost_")
        || value.contains("winappruntime")
}

fn normalize_uwp_display_name(
    raw_display: Option<String>,
    pkg: &windows::ApplicationModel::Package,
    family_name: &str,
) -> String {
    let trimmed = raw_display
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("");

    if trimmed.is_empty() {
        return family_name.to_owned();
    }
    // Many packaged apps expose an unresolved "ms-resource:" token via
    // Package.DisplayName(). When that happens, prefer manifest
    // Properties/DisplayName if it is a concrete user-facing string.
    if trimmed.starts_with("ms-resource:") {
        if let Some(manifest_name) = read_uwp_manifest_display_name(pkg) {
            return manifest_name;
        }
    }
    trimmed.to_owned()
}

/// True when a UWP family name looks like an opaque system component
/// rather than a real user-facing app — GUID-prefixed packages
/// (`{8-4-4-4-12}_pubid`) or names that begin with `Windows.Internal`.
///
/// These packages routinely ship without a meaningful `DisplayName` /
/// `Properties/DisplayName` (e.g. `CredentialDialogHost`,
/// `CloudExperienceHost`, internal language shims), so they fall through
/// `normalize_uwp_display_name`'s fallbacks to the family name itself.
/// Reporting that in `list_apps` is just noise — agents can't usefully
/// launch them and they crowd out actual installed apps.
fn looks_like_opaque_system_family(family_name: &str) -> bool {
    // Strip the publisher suffix (`_pubid`) before testing the
    // package-name half — that's where the GUID lives.
    let pkg_name = family_name.split('_').next().unwrap_or(family_name);

    // `Windows.Internal.*` is Microsoft's own conventional namespace
    // for internal-only packages.
    if pkg_name.starts_with("Windows.Internal") {
        return true;
    }

    // GUID pattern: 8-4-4-4-12 hex with `-` separators.
    let mut parts = pkg_name.splitn(5, '-');
    let segs = [
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    ];
    let expected_lens = [8, 4, 4, 4, 12];
    let all_hex = segs
        .iter()
        .zip(expected_lens.iter())
        .all(|(s, &n)| s.len() == n && s.chars().all(|c| c.is_ascii_hexdigit()));
    all_hex
}

/// Best-effort parse of AppxManifest.xml to extract `<Properties><DisplayName>`.
fn read_uwp_manifest_display_name(pkg: &windows::ApplicationModel::Package) -> Option<String> {
    let base = pkg.InstalledPath().ok()?.to_string();
    if base.is_empty() {
        return None;
    }
    let manifest = std::path::Path::new(&base).join("AppxManifest.xml");
    let xml = std::fs::read_to_string(manifest).ok()?;
    let key = "<DisplayName>";
    let start = xml.find(key)? + key.len();
    let rest = &xml[start..];
    let end = rest.find("</DisplayName>")?;
    let value = rest[..end].trim();
    if value.is_empty() || value.starts_with("ms-resource:") {
        None
    } else {
        Some(value.to_owned())
    }
}
/// Resolve a UWP package's install-path mtime to an RFC3339 string.
fn read_install_mtime(pkg: &windows::ApplicationModel::Package) -> Option<String> {
    let path_hstring = pkg.InstalledPath().ok()?;
    let path = path_hstring.to_string();
    if path.is_empty() {
        return None;
    }
    let meta = std::fs::metadata(&path).ok()?;
    let modified = meta.modified().ok()?;
    let duration = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    cua_driver_core::timestamp::unix_secs_to_rfc3339(duration.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    #[test]
    fn parses_every_uwp_application_entry_and_executable() {
        let entries = parse_uwp_application_entries(
            r#"
            <Package>
              <Applications>
                <Application Id="Main" Executable="app.exe" />
                <Application Id="Secondary" Executable="nested\secondary.exe" />
              </Applications>
            </Package>
            "#,
        );
        assert_eq!(
            entries,
            vec![
                ("Main".to_owned(), "app.exe".to_owned()),
                ("Secondary".to_owned(), r"nested\secondary.exe".to_owned()),
            ]
        );
    }

    #[test]
    fn catalog_dedupe_preserves_distinct_shortcut_arguments() {
        let first = InstalledApp {
            name: "Chrome Profile 1".to_owned(),
            bundle_id: r"C:\Chrome\chrome.exe".to_owned(),
            kind: "desktop".to_owned(),
            launch_path: r#""C:\Chrome\chrome.exe" --profile-directory="Profile 1""#.to_owned(),
            last_used: None,
            modified_at: None,
            uwp_executables: Vec::new(),
        };
        let second = InstalledApp {
            name: "Chrome Profile 2".to_owned(),
            bundle_id: first.bundle_id.clone(),
            kind: first.kind.clone(),
            launch_path: r#""C:\Chrome\chrome.exe" --profile-directory="Profile 2""#.to_owned(),
            last_used: None,
            modified_at: None,
            uwp_executables: Vec::new(),
        };
        let duplicate = first.clone();
        let mut apps = vec![first, second, duplicate];
        dedupe_installed_apps(&mut apps);
        assert_eq!(apps.len(), 2);
        assert_ne!(apps[0].launch_path, apps[1].launch_path);
    }

    #[test]
    fn primary_uwp_entry_prefers_app_and_skips_internal_activations() {
        let entries = vec![
            (
                "Example".to_owned(),
                "Vendor.Example_pub!Global.ShellMcpServers".to_owned(),
                "server.exe".to_owned(),
            ),
            (
                "Example".to_owned(),
                "Vendor.Example_pub!App".to_owned(),
                "example.exe".to_owned(),
            ),
        ];
        assert_eq!(select_primary_uwp_application(&entries), 1);
        assert!(looks_like_internal_uwp_application_id(
            "Global.ShellMcpServers"
        ));
        assert!(looks_like_system_component_family(
            "MicrosoftWindows.Client.Core_cw5n1h2txyewy"
        ));
        assert!(!looks_like_system_component_family(
            "Microsoft.Paint_8wekyb3d8bbwe"
        ));
    }

    #[test]
    fn shortcut_environment_target_resolves_without_changing_arguments() {
        unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }
            .ok()
            .expect("initialize COM for shortcut resolution");
        struct Apartment;
        impl Drop for Apartment {
            fn drop(&mut self) {
                unsafe { CoUninitialize() };
            }
        }
        let _apartment = Apartment;
        let directory = tempfile::tempdir().expect("create shortcut fixture directory");
        let link_path = directory.path().join("Environment target.lnk");
        let link_path_wide = to_wide_nul(link_path.to_str().expect("fixture path is UTF-8"));
        let target = to_wide_nul(r"%windir%\system32\cmd.exe");
        let expected = PathBuf::from(std::env::var_os("windir").expect("Windows directory"))
            .join("system32")
            .join("cmd.exe")
            .canonicalize()
            .expect("Windows command processor exists");

        for arguments in ["", r#"/d /c echo "argument with spaces""#] {
            let link: IShellLinkW = unsafe {
                CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).expect("create shell link")
            };
            let arguments_wide = to_wide_nul(arguments);
            let persist: IPersistFile = link.cast().expect("shell link persistence");
            unsafe {
                link.SetPath(PCWSTR(target.as_ptr()))
                    .expect("set environment target");
                link.SetArguments(PCWSTR(arguments_wide.as_ptr()))
                    .expect("set arguments");
                persist
                    .Save(PCWSTR(link_path_wide.as_ptr()), true)
                    .expect("save shortcut");
                let mut raw = vec![0u16; MAX_PATH as usize + 1];
                link.GetPath(
                    &mut raw,
                    std::ptr::null_mut(),
                    windows::Win32::UI::Shell::SLGP_RAWPATH.0 as u32,
                )
                .expect("inspect raw target");
                assert!(
                    decode_wstr(&raw).starts_with('%'),
                    "fixture must preserve its environment token"
                );
            }

            let app = resolve_lnk(&link_path).expect("discover environment shortcut");
            assert_eq!(
                PathBuf::from(&app.bundle_id)
                    .canonicalize()
                    .expect("resolved executable exists"),
                expected
            );
            assert!(!app.launch_path.contains("%windir%"));
            if !arguments.is_empty() {
                assert!(app.launch_path.ends_with(&format!(" {arguments}")));
            }
        }
    }

    #[test]
    fn wedged_uwp_scan_has_bounded_worker_growth_and_recovers() {
        let gate = Arc::new(SingleFlight::new(Duration::from_millis(500)));
        let starts = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let starts_for_worker = Arc::clone(&starts);
        let active_for_worker = Arc::clone(&active);
        let max_active_for_worker = Arc::clone(&max_active);
        let first = run_uwp_scan(&gate, Duration::from_millis(20), move || {
            starts_for_worker.fetch_add(1, Ordering::SeqCst);
            let now_active = active_for_worker.fetch_add(1, Ordering::SeqCst) + 1;
            max_active_for_worker.fetch_max(now_active, Ordering::SeqCst);
            started_tx
                .send(())
                .expect("test should observe worker start");
            release_rx.recv().expect("test should release worker");
            active_for_worker.fetch_sub(1, Ordering::SeqCst);
            7
        });

        assert_eq!(first, Err(UwpScanDeadlineError::Timeout));
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker should have started");

        for _ in 0..100 {
            assert_eq!(
                run_uwp_scan(&gate, Duration::from_millis(20), || 99),
                Err(UwpScanDeadlineError::Busy)
            );
        }
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(max_active.load(Ordering::SeqCst), 1);

        release_tx
            .send(())
            .expect("worker should still be listening");
        let wait_deadline = Instant::now() + Duration::from_secs(1);
        while gate.is_in_flight() && Instant::now() < wait_deadline {
            thread::yield_now();
        }
        assert!(!gate.is_in_flight());
        assert_eq!(
            run_uwp_scan(&gate, Duration::from_millis(20), || 99),
            Err(UwpScanDeadlineError::Busy),
            "a late return should enter cooldown"
        );

        thread::sleep(Duration::from_millis(600));
        assert_eq!(run_uwp_scan(&gate, Duration::from_secs(1), || 42), Ok(42));
        assert_eq!(max_active.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn opaque_system_family_matches_guid_prefix() {
        // Both real-world examples seen on a stock Win11 image where
        // Package.DisplayName resolved to an unresolved ms-resource:
        // token and AppxManifest.xml didn't have a Properties/DisplayName.
        assert!(looks_like_opaque_system_family(
            "1527c705-839a-4832-9118-54d4Bd6a0c89_cw5n1h2txyewy"
        ));
        assert!(looks_like_opaque_system_family(
            "F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE_cw5n1h2txyewy"
        ));
    }

    #[test]
    fn opaque_system_family_matches_internal_namespace() {
        assert!(looks_like_opaque_system_family(
            "Windows.Internal.ShellExperience_cw5n1h2txyewy"
        ));
        assert!(looks_like_opaque_system_family(
            "Windows.Internal.PrintingFramework_cw5n1h2txyewy"
        ));
    }

    #[test]
    fn opaque_system_family_keeps_real_apps() {
        // Familiar packaged apps must NOT be filtered out — their family
        // names don't look like GUIDs and don't start with the internal
        // prefix.
        assert!(!looks_like_opaque_system_family(
            "Microsoft.WindowsNotepad_8wekyb3d8bbwe"
        ));
        assert!(!looks_like_opaque_system_family(
            "Microsoft.WindowsCalculator_8wekyb3d8bbwe"
        ));
        assert!(!looks_like_opaque_system_family(
            "Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe"
        ));
        assert!(!looks_like_opaque_system_family(
            "SpotifyAB.SpotifyMusic_zpdnekdrzrea0"
        ));
    }

    #[test]
    fn opaque_system_family_handles_missing_publisher_suffix() {
        // No underscore = no publisher half. Still examine the whole
        // string for the GUID / internal-namespace shape.
        assert!(looks_like_opaque_system_family(
            "1527c705-839a-4832-9118-54d4Bd6a0c89"
        ));
        assert!(!looks_like_opaque_system_family("Microsoft.WindowsNotepad"));
        assert!(!looks_like_opaque_system_family(""));
    }
}
