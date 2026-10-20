//! The static update manifest, built from what the bundler actually wrote.
//!
//! `tauri-plugin-updater` looks a platform up as `{os}-{arch}-{bundle_type}` and
//! falls back to `{os}-{arch}` (see its `Updater::get_urls`). The bundle type
//! names are the ones its `Installer` enum uses: `appimage`, `deb`, `rpm`, `app`,
//! `msi`, `nsis`. This module fills the same keys from the filenames and reads
//! each signature beside its bundle, because the manifest carries the signature
//! text rather than a URL to it.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use serde::Serialize;

/// Everything the manifest needs that cannot be read off the bundle directory.
#[derive(Debug, Clone)]
pub struct Options {
    /// The bundle root, normally `client/target/release/bundle`.
    pub bundles: PathBuf,
    /// `owner/name`, used in the default asset URLs.
    pub repo: String,
    /// The git tag the assets are published under.
    pub tag: String,
    /// The version written into the manifest; must match the app's version.
    pub version: String,
    /// Release notes, if the caller has any.
    pub notes: Option<String>,
    /// The architecture of the macOS `.app.tar.gz`, whose name does not carry one.
    pub mac_arch: String,
    /// Overrides `https://github.com/{repo}/releases/download`.
    pub base_url: Option<String>,
    /// Overrides the current time, for tests and reproducible reruns.
    pub pub_date: Option<String>,
}

/// One platform entry: the signature text and the signed bundle's URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Platform {
    pub signature: String,
    pub url: String,
}

/// The static JSON read by `tauri-plugin-updater`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Manifest {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub pub_date: String,
    pub platforms: BTreeMap<String, Platform>,
}

/// Scans `opts.bundles`, pairs every updatable bundle with its `.sig` and returns
/// the manifest. Fails rather than writing a manifest that promises a file the
/// updater cannot install.
pub fn build(opts: &Options) -> Result<Manifest> {
    check_options(opts)?;

    let base = match &opts.base_url {
        Some(base) => base.trim_end_matches('/').to_owned(),
        None => format!(
            "https://github.com/{}/releases/download",
            opts.repo.trim_end_matches('/')
        ),
    };

    let mut platforms = BTreeMap::new();
    let mut files = Vec::new();
    collect_files(&opts.bundles, &mut files)?;
    files.sort();

    for path in files {
        let name = file_name(&path)?;
        let Some((os, bundle)) = classify(name) else {
            continue;
        };
        let arch = if os == "darwin" {
            opts.mac_arch.as_str()
        } else {
            arch_from_name(name)
                .with_context(|| format!("cannot tell the architecture from {name:?}"))?
        };

        let signature = read_signature(&path)?;
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c))
        {
            bail!("bundle name {name:?} is not URL-safe");
        }
        let key = format!("{os}-{arch}-{bundle}");
        let url = format!("{base}/{}/{}", opts.tag, name);
        let platform = Platform { signature, url };

        if let Some(previous) = platforms.insert(key.clone(), platform) {
            bail!(
                "two bundles would publish as {key}: {} and {}",
                previous.url,
                name
            );
        }
    }

    if platforms.is_empty() {
        bail!(
            "no updatable bundle under {}: expected an .AppImage, .deb, .rpm or .app.tar.gz",
            opts.bundles.display()
        );
    }

    Ok(Manifest {
        version: opts.version.clone(),
        notes: opts.notes.clone(),
        pub_date: match &opts.pub_date {
            Some(date) => date.clone(),
            None => now_rfc3339()?,
        },
        platforms,
    })
}

fn check_options(opts: &Options) -> Result<()> {
    if opts.version.trim().is_empty() {
        bail!("--version must not be empty");
    }
    if opts.version.chars().any(char::is_whitespace) {
        bail!("--version must not contain whitespace: {:?}", opts.version);
    }

    if !opts
        .tag
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
    {
        bail!(
            "--tag may only contain letters, digits, '.', '-' and '_': {:?}",
            opts.tag
        );
    }
    if opts.tag.is_empty() {
        bail!("--tag must not be empty");
    }

    let mut parts = opts.repo.split('/');
    let owner = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if owner.is_empty() || name.is_empty() || parts.next().is_some() {
        bail!("--repo must be owner/name, got {:?}", opts.repo);
    }

    if !matches!(opts.mac_arch.as_str(), "x86_64" | "aarch64") {
        bail!(
            "--mac-arch must be x86_64 or aarch64, got {:?}",
            opts.mac_arch
        );
    }

    if let Some(base) = &opts.base_url {
        if !base.starts_with("https://") {
            bail!("--base-url must be https, got {base:?}");
        }
    }

    Ok(())
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir)
        .with_context(|| format!("cannot read the bundle directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("cannot read {}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// `(os, bundle_type)` for an artefact the updater can install, or `None` for
/// everything else the bundler leaves behind (signatures, unpacked trees).
fn classify(name: &str) -> Option<(&'static str, &'static str)> {
    if name.ends_with(".AppImage") {
        return Some(("linux", "appimage"));
    }
    if name.ends_with(".deb") {
        return Some(("linux", "deb"));
    }
    if name.ends_with(".rpm") {
        return Some(("linux", "rpm"));
    }
    if name.ends_with(".app.tar.gz") {
        return Some(("darwin", "app"));
    }
    None
}

/// The architecture as the updater spells it, read from a bundle filename:
/// `amd64`/`x86_64` and `arm64`/`aarch64` appear in Tauri's and RPM's names.
fn arch_from_name(name: &str) -> Option<&'static str> {
    if name.contains("x86_64") || name.contains("amd64") {
        Some("x86_64")
    } else if name.contains("aarch64") || name.contains("arm64") {
        Some("aarch64")
    } else {
        None
    }
}

fn file_name(path: &Path) -> Result<&str> {
    path.file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("bundle name is not UTF-8: {}", path.display()))
}

fn read_signature(bundle: &Path) -> Result<String> {
    let sig = PathBuf::from(format!("{}.sig", bundle.display()));
    let text = fs::read_to_string(&sig).with_context(|| {
        format!(
            "{} has no signature at {} — build with createUpdaterArtifacts and a signing key",
            bundle.display(),
            sig.display()
        )
    })?;
    let text = text.trim().to_owned();
    if text.is_empty() {
        bail!("{} is empty", sig.display());
    }
    Ok(text)
}

fn now_rfc3339() -> Result<String> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("the system clock is before 1970")?
        .as_secs();
    Ok(rfc3339(seconds))
}

/// RFC 3339 in UTC with second precision, without pulling in a date library.
fn rfc3339(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap_or(i64::MAX);
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a calendar date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, sig) in [
            (
                "appimage/Syncbox_0.2.0_amd64.AppImage",
                "appimage-signature",
            ),
            ("deb/Syncbox_0.2.0_amd64.deb", "deb-signature"),
            ("macos/Syncbox.app.tar.gz", "mac-signature"),
        ] {
            let path = dir.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"bundle").unwrap();
            fs::write(format!("{}.sig", path.display()), format!("{sig}\n")).unwrap();
        }
        dir
    }

    fn options(dir: &Path) -> Options {
        Options {
            bundles: dir.to_owned(),
            repo: "cmspeedau/SyncBox".into(),
            tag: "desktop-v0.2.0".into(),
            version: "0.2.0".into(),
            notes: None,
            mac_arch: "x86_64".into(),
            base_url: None,
            pub_date: Some("2026-10-20T00:00:00Z".into()),
        }
    }

    #[test]
    fn every_bundle_kind_gets_the_key_the_updater_looks_up() {
        let dir = fixture();
        let manifest = build(&options(dir.path())).unwrap();

        let keys: Vec<_> = manifest.platforms.keys().cloned().collect();
        assert_eq!(
            keys,
            [
                "darwin-x86_64-app",
                "linux-x86_64-appimage",
                "linux-x86_64-deb"
            ]
        );

        let deb = &manifest.platforms["linux-x86_64-deb"];
        assert_eq!(deb.signature, "deb-signature");
        assert_eq!(
            deb.url,
            "https://github.com/cmspeedau/SyncBox/releases/download/desktop-v0.2.0/Syncbox_0.2.0_amd64.deb"
        );
    }

    #[test]
    fn the_manifest_carries_what_tauri_requires() {
        let dir = fixture();
        let manifest = build(&options(dir.path())).unwrap();
        let json: serde_json::Value = serde_json::to_value(&manifest).unwrap();

        assert_eq!(json["version"], "0.2.0");
        assert_eq!(json["pub_date"], "2026-10-20T00:00:00Z");
        assert!(json.get("notes").is_none(), "an absent note stays absent");
        for platform in [
            "darwin-x86_64-app",
            "linux-x86_64-appimage",
            "linux-x86_64-deb",
        ] {
            let entry = &json["platforms"][platform];
            assert!(entry["url"].as_str().unwrap().starts_with("https://"));
            assert!(!entry["signature"].as_str().unwrap().is_empty());
        }
    }

    #[test]
    fn a_base_url_can_point_at_another_mirror() {
        let dir = fixture();
        let mut opts = options(dir.path());
        opts.base_url = Some("https://mirror.example/syncbox/".into());
        let manifest = build(&opts).unwrap();

        assert_eq!(
            manifest.platforms["linux-x86_64-appimage"].url,
            "https://mirror.example/syncbox/desktop-v0.2.0/Syncbox_0.2.0_amd64.AppImage"
        );
    }

    #[test]
    fn a_bundle_without_its_signature_is_refused_by_name() {
        let dir = fixture();
        fs::remove_file(dir.path().join("deb/Syncbox_0.2.0_amd64.deb.sig")).unwrap();

        let error = build(&options(dir.path())).unwrap_err().to_string();
        assert!(error.contains("Syncbox_0.2.0_amd64.deb"), "{error}");
        assert!(error.contains("no signature"), "{error}");
    }

    #[test]
    fn two_bundles_for_one_target_are_refused_rather_than_one_silently_winning() {
        let dir = fixture();
        fs::write(
            dir.path().join("appimage/Syncbox_0.1.0_amd64.AppImage"),
            b"bundle",
        )
        .unwrap();
        fs::write(
            dir.path().join("appimage/Syncbox_0.1.0_amd64.AppImage.sig"),
            b"old-signature",
        )
        .unwrap();

        let error = build(&options(dir.path())).unwrap_err().to_string();
        assert!(error.contains("linux-x86_64-appimage"), "{error}");
        assert!(error.contains("two bundles"), "{error}");
    }

    #[test]
    fn a_linux_bundle_with_no_arch_in_its_name_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Syncbox.deb");
        fs::write(&path, b"bundle").unwrap();
        fs::write(format!("{}.sig", path.display()), b"sig").unwrap();

        let error = build(&options(dir.path())).unwrap_err().to_string();
        assert!(error.contains("architecture"), "{error}");
        assert!(error.contains("Syncbox.deb"), "{error}");
    }

    #[test]
    fn macos_bundles_take_the_architecture_the_caller_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Syncbox.app.tar.gz");
        fs::write(&path, b"bundle").unwrap();
        fs::write(format!("{}.sig", path.display()), b"sig").unwrap();

        let mut opts = options(dir.path());
        opts.mac_arch = "aarch64".into();
        let manifest = build(&opts).unwrap();
        assert!(manifest.platforms.contains_key("darwin-aarch64-app"));
    }

    #[test]
    fn an_insecure_base_url_is_refused() {
        let dir = fixture();
        let mut opts = options(dir.path());
        opts.base_url = Some("http://mirror.example/syncbox".into());
        let error = build(&opts).unwrap_err().to_string();
        assert!(error.contains("https"), "{error}");
    }

    #[test]
    fn a_filename_that_would_not_survive_a_url_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Syncbox 0.1.0 amd64.deb");
        fs::write(&path, b"bundle").unwrap();
        fs::write(format!("{}.sig", path.display()), b"sig").unwrap();

        let error = build(&options(dir.path())).unwrap_err().to_string();
        assert!(error.contains("not URL-safe"), "{error}");
    }

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(1_767_225_600), "2026-01-01T00:00:00Z");
    }
}
