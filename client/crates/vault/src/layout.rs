//! Paths inside a vault, with no filesystem access so they can be tested
//! without touching a disk.
//!
//! The shape follows Cryptomator: encrypted files live in a directory named for
//! their directory id, and every directory also drops an empty marker file under
//! `d/`, sharded by the first four characters of its id so a filesystem with a
//! per-directory entry limit still copes.

use std::path::{Path, PathBuf};

use syncbox_crypto::names::{DIR_MARKER_DIR, FILE_SUFFIX, LONG_NAME_SUFFIX};

/// Ciphertext name of a file, given its already-encrypted name.
#[must_use]
pub fn cipher_file_name(encrypted_name: &str) -> String {
    format!("{encrypted_name}{FILE_SUFFIX}")
}

/// Directory that holds the ciphertext files of one directory id.
#[must_use]
pub fn cipher_dir(root: &Path, dir_id: &str) -> PathBuf {
    root.join(dir_id)
}

/// Marker file proving a directory exists, sharded two characters at a time.
///
/// With an id shorter than four characters the remaining shard is simply
/// omitted, which keeps the function total rather than requiring a valid id.
#[must_use]
pub fn marker_path(root: &Path, dir_id: &str) -> PathBuf {
    let first = dir_id.get(0..2).unwrap_or(dir_id);
    let second = dir_id.get(2..4).unwrap_or("");

    let mut path = root.join(DIR_MARKER_DIR).join(first);
    if !second.is_empty() {
        path = path.join(second);
    }
    path.join(format!("{dir_id}{FILE_SUFFIX}"))
}

/// True for an encrypted file entry.
///
/// A marker file has the same name shape; the two are told apart by their parent
/// directory, which the caller knows and this function does not.
#[must_use]
pub fn is_cipher_file(name: &str) -> bool {
    name.ends_with(FILE_SUFFIX) && !is_long_name_entry(name)
}

/// True for the indirection directory an over-long encrypted name becomes.
#[must_use]
pub fn is_long_name_entry(name: &str) -> bool {
    name.ends_with(LONG_NAME_SUFFIX)
}

/// Strips the ciphertext suffix, leaving the encrypted name.
#[must_use]
pub fn strip_cipher_suffix(name: &str) -> &str {
    name.strip_suffix(FILE_SUFFIX)
        .or_else(|| name.strip_suffix(LONG_NAME_SUFFIX))
        .unwrap_or(name)
}

/// True when a name belongs to vault bookkeeping rather than to a user file.
#[must_use]
pub fn is_internal(name: &str) -> bool {
    name == crate::config::CONFIG_FILE_NAME || name == DIR_MARKER_DIR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_take_the_cipher_suffix() {
        assert_eq!(cipher_file_name("ABCDEFGH"), "ABCDEFGH.c9r");
    }

    #[test]
    fn markers_are_sharded_by_id_prefix() {
        let root = Path::new("/vault");
        assert_eq!(
            marker_path(root, "ABCDEFGHIJ"),
            PathBuf::from("/vault/d/AB/CD/ABCDEFGHIJ.c9r")
        );
        // Short ids must not panic; the second shard is simply left out.
        assert_eq!(marker_path(root, "AB"), PathBuf::from("/vault/d/AB/AB.c9r"));
        assert_eq!(marker_path(root, ""), PathBuf::from("/vault/d/.c9r"));
    }

    #[test]
    fn ciphertext_files_are_recognised() {
        assert!(is_cipher_file("ABCDEFGH.c9r"));
        assert!(!is_cipher_file("notes.txt"));
        assert!(!is_cipher_file("VERYLONGNAME.c9s"));
    }

    #[test]
    fn long_name_indirection_is_recognised() {
        assert!(is_long_name_entry("SOMELONGNAME.c9s"));
        assert!(!is_long_name_entry("SOMELONGNAME.c9r"));
    }

    #[test]
    fn suffix_stripping_is_total() {
        assert_eq!(strip_cipher_suffix("AB.c9r"), "AB");
        assert_eq!(strip_cipher_suffix("AB.c9s"), "AB");
        assert_eq!(strip_cipher_suffix("AB"), "AB");
    }

    #[test]
    fn bookkeeping_entries_are_excluded_from_a_user_listing() {
        assert!(is_internal("vault.json"));
        assert!(is_internal("d"));
        assert!(!is_internal("ABCDEFGH"));
    }
}
