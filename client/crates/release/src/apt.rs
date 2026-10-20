//! A flat apt repository built from the one `.deb` a release carries.
//!
//! The repository is flat on purpose: `Packages` sits at the root of a stable
//! download URL and `Filename` names an asset in the same release, so there is no
//! `dists/` tree or `pool/` to keep in step. `apt` reads it as
//! `deb [signed-by=…] <url> ./`.
//!
//! Signing is not done here. The workflow imports the archive key, then signs the
//! `Release` this module writes (`Release.gpg` and `InRelease`) with `gpg`, where
//! the passphrase never has to pass through this program.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use flate2::{write::GzEncoder, Compression};
use sha2::{Digest, Sha256};

use crate::time;

/// Inputs to the index: the artefact itself and the control paragraph inside it.
#[derive(Debug, Clone)]
pub struct AptOptions {
    /// The `.deb` that the index will describe; its filename becomes `Filename:`.
    pub deb: PathBuf,
    /// The package's control paragraph, usually extracted from the `.deb`.
    pub control: String,
    /// Where `Packages`, `Packages.gz` and `Release` are written.
    pub out_dir: PathBuf,
    /// `Suite:` and `Codename:`; `stable` unless a release channel says otherwise.
    pub suite: String,
    /// `Origin:` and the first word of the description.
    pub origin: String,
    /// `Label:`, normally the product name.
    pub label: String,
    /// An RFC 2822 `Date:`, instead of now. The tests pin it.
    pub date: Option<String>,
}

/// The three files written for the repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AptIndex {
    pub packages: PathBuf,
    pub packages_gz: PathBuf,
    pub release: PathBuf,
}

/// Writes `Packages`, `Packages.gz` and `Release` for `opts.deb`.
pub fn build(opts: &AptOptions) -> Result<AptIndex> {
    let control = normalize_control(&opts.control)?;
    let package = field(&control, "Package").context("control has no Package: field")?;
    let version = field(&control, "Version").context("control has no Version: field")?;
    let arch = field(&control, "Architecture").context("control has no Architecture: field")?;

    check_token("Package", package)?;
    check_token("Version", version)?;
    check_token("Architecture", arch)?;
    check_token("Suite", &opts.suite)?;

    let deb_name = opts
        .deb
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("the deb name is not UTF-8: {}", opts.deb.display()))?;
    if !deb_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._+~-".contains(c))
    {
        bail!("the deb name {deb_name:?} is not URL-safe");
    }

    let bytes = fs::read(&opts.deb)
        .with_context(|| format!("cannot read the deb at {}", opts.deb.display()))?;
    let size = bytes.len();
    let deb_sha = hex(&Sha256::digest(&bytes));

    // The control paragraph plus the three fields apt derives from the file itself.
    let packages = format!("{control}\nFilename: {deb_name}\nSize: {size}\nSHA256: {deb_sha}\n\n");
    let packages_gz = gzip(packages.as_bytes())?;
    let release = format!(
        "Origin: {origin}\nLabel: {label}\nSuite: {suite}\nCodename: {suite}\nDate: {date}\n\
         Architectures: {arch}\nComponents: main\nDescription: {label} desktop packages\n\
         SHA256:\n {packages_sha} {packages_size} Packages\n {gz_sha} {gz_size} Packages.gz\n",
        origin = opts.origin,
        label = opts.label,
        suite = opts.suite,
        date = match &opts.date {
            Some(date) => date.clone(),
            None => time::rfc2822(time::now()?),
        },
        arch = arch,
        packages_sha = hex(&Sha256::digest(packages.as_bytes())),
        packages_size = packages.len(),
        gz_sha = hex(&Sha256::digest(&packages_gz)),
        gz_size = packages_gz.len(),
    );

    fs::create_dir_all(&opts.out_dir)
        .with_context(|| format!("cannot create {}", opts.out_dir.display()))?;
    let packages_path = write(&opts.out_dir, "Packages", packages.as_bytes())?;
    let gz_path = write(&opts.out_dir, "Packages.gz", &packages_gz)?;
    let release_path = write(&opts.out_dir, "Release", release.as_bytes())?;

    Ok(AptIndex {
        packages: packages_path,
        packages_gz: gz_path,
        release: release_path,
    })
}

/// One field's value; the first occurrence wins, continuation lines are ignored.
fn field<'a>(control: &'a str, name: &str) -> Option<&'a str> {
    control.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == name)
            .then(|| value.trim())
            .filter(|v| !v.is_empty())
    })
}

/// Drops a trailing blank line and any CR from a copied control paragraph.
fn normalize_control(control: &str) -> Result<String> {
    let control = control.replace("\r\n", "\n").trim().to_owned();
    if control.is_empty() {
        bail!("the control paragraph is empty");
    }
    Ok(control)
}

fn check_token(field_name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        bail!("{field_name}: must be one word, got {value:?}");
    }
    Ok(())
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bytes).context("cannot gzip Packages")?;
    encoder.finish().context("cannot finish Packages.gz")
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    let path = dir.join(name);
    fs::write(&path, bytes).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    const CONTROL: &str = concat!(
        "Package: syncbox\n",
        "Version: 0.2.0\n",
        "Architecture: amd64\n",
        "Maintainer: Syncbox <hello@example.com>\n",
        "Depends: libwebkit2gtk-4.1-0, libgtk-3-0\n",
        "Section: utils\n",
        "Priority: optional\n",
        "Description: Syncbox desktop\n",
        " A folder that syncs.\n",
    );

    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let deb = dir.path().join("Syncbox_0.2.0_amd64.deb");
        fs::write(&deb, b"package-bytes").unwrap();
        (dir, deb)
    }

    fn options(dir: &Path, deb: &Path) -> AptOptions {
        AptOptions {
            deb: deb.to_owned(),
            control: CONTROL.into(),
            out_dir: dir.join("apt"),
            suite: "stable".into(),
            origin: "Syncbox".into(),
            label: "Syncbox".into(),
            date: Some("Tue, 20 Oct 2026 00:00:00 UTC".into()),
        }
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn packages_keeps_the_control_and_adds_the_file_fields() {
        let (dir, deb) = fixture();
        let index = build(&options(dir.path(), &deb)).unwrap();
        let packages = read(&index.packages);

        assert!(packages.starts_with(CONTROL.trim()), "{packages}");
        assert!(packages.contains("\nFilename: Syncbox_0.2.0_amd64.deb\n"));
        assert!(packages.contains("\nSize: 13\n"));
        assert!(packages.contains(&format!(
            "\nSHA256: {}\n",
            hex(&Sha256::digest(b"package-bytes"))
        )));
        assert!(packages.ends_with("\n\n"), "one blank line between entries");
    }

    #[test]
    fn packages_gz_is_the_same_text() {
        let (dir, deb) = fixture();
        let index = build(&options(dir.path(), &deb)).unwrap();
        let mut decoded = String::new();
        flate2::read::GzDecoder::new(fs::File::open(&index.packages_gz).unwrap())
            .read_to_string(&mut decoded)
            .unwrap();

        assert_eq!(decoded, read(&index.packages));
    }

    #[test]
    fn release_checksums_both_index_files() {
        let (dir, deb) = fixture();
        let index = build(&options(dir.path(), &deb)).unwrap();
        let release = read(&index.release);
        let packages = fs::read(&index.packages).unwrap();
        let gz = fs::read(&index.packages_gz).unwrap();

        assert!(release.contains("Suite: stable\n"));
        assert!(release.contains("Architectures: amd64\n"));
        assert!(release.contains("Date: Tue, 20 Oct 2026 00:00:00 UTC\n"));
        assert!(release.contains(&format!(
            " {} {} Packages\n",
            hex(&Sha256::digest(&packages)),
            packages.len()
        )));
        assert!(release.contains(&format!(
            " {} {} Packages.gz\n",
            hex(&Sha256::digest(&gz)),
            gz.len()
        )));
    }

    #[test]
    fn a_control_without_an_architecture_is_refused() {
        let (dir, deb) = fixture();
        let mut opts = options(dir.path(), &deb);
        opts.control = "Package: syncbox\nVersion: 0.2.0\n".into();

        let error = build(&opts).unwrap_err().to_string();
        assert!(error.contains("Architecture"), "{error}");
    }

    #[test]
    fn a_package_name_with_a_space_is_refused() {
        let (dir, deb) = fixture();
        let mut opts = options(dir.path(), &deb);
        opts.control = CONTROL.replace("Package: syncbox", "Package: sync box");

        let error = build(&opts).unwrap_err().to_string();
        assert!(error.contains("Package: must be one word"), "{error}");
    }

    #[test]
    fn the_deb_must_exist() {
        let (dir, _) = fixture();
        let missing = dir.path().join("missing.deb");
        let error = build(&options(dir.path(), &missing))
            .unwrap_err()
            .to_string();
        assert!(error.contains("missing.deb"), "{error}");
    }

    #[test]
    fn a_control_paragraph_copied_with_crlf_still_works() {
        let (dir, deb) = fixture();
        let mut opts = options(dir.path(), &deb);
        opts.control = CONTROL.replace('\n', "\r\n");

        let index = build(&opts).unwrap();
        assert!(!read(&index.packages).contains('\r'));
    }
}
