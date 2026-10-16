//! End-to-end composition test: the primitives in `syncbox-crypto` and the path
//! helpers in `syncbox-vault` together map a plaintext path to a ciphertext path,
//! and back, with no gaps. This is the property the sync engine (M3) leans on, so
//! it is worth pinning the moment both halves exist.

use std::path::Path;

use syncbox_crypto::keys::MasterKeys;
use syncbox_crypto::names::{child_dir_id, decrypt_filename, encrypt_filename, DirId};
use syncbox_vault::layout;

/// The ciphertext directory a plaintext directory resolves to: walk each component,
/// encrypting its name for the current directory and deriving the child id.
fn dir_id_for(
    hmac: &syncbox_crypto::MasterKey,
    primary: &syncbox_crypto::MasterKey,
    chain: &[&str],
) -> DirId {
    let mut dir = DirId::root(hmac).unwrap();
    for component in chain {
        let encrypted = encrypt_filename(primary, &dir, component).unwrap();
        dir = child_dir_id(hmac, &dir, &encrypted).unwrap();
    }
    dir
}

#[test]
fn a_file_path_maps_to_ciphertext_and_back() {
    let keys = MasterKeys::generate().unwrap();
    let root = Path::new("/vault");

    // plaintext: Documents/2026/meeting notes.txt
    let dirs = ["Documents", "2026"];
    let name = "meeting notes.txt";

    let parent_id = dir_id_for(&keys.hmac, &keys.primary, &dirs);
    let cipher_name = encrypt_filename(&keys.primary, &parent_id, name).unwrap();
    let cipher_path =
        layout::cipher_dir(root, parent_id.as_str()).join(layout::cipher_file_name(&cipher_name));

    // The on-disk name is the ciphertext plus the `.c9r` suffix, and it lives under
    // a directory named for the parent id — nothing about the plaintext leaks.
    assert!(cipher_path.starts_with(root));
    let stored = cipher_path.file_name().unwrap().to_str().unwrap();
    assert!(stored.ends_with(".c9r"));
    assert!(!stored.contains("meeting"));

    // And it is recoverable: strip the suffix, decrypt in the same directory.
    let recovered = decrypt_filename(
        &keys.primary,
        &parent_id,
        &stored[..stored.len() - ".c9r".len()],
    )
    .unwrap();
    assert_eq!(recovered, name);
}

#[test]
fn the_same_name_under_different_parents_lands_in_different_directories() {
    let keys = MasterKeys::generate().unwrap();
    let root = Path::new("/vault");

    let in_docs = dir_id_for(&keys.hmac, &keys.primary, &["Documents"]);
    let in_pics = dir_id_for(&keys.hmac, &keys.primary, &["Pictures"]);

    // A file literally named the same in two folders gets a different ciphertext
    // name and a different parent directory, so the two are indistinguishable on
    // disk to anyone without the keys.
    let cipher_docs = encrypt_filename(&keys.primary, &in_docs, "todo.txt").unwrap();
    let cipher_pics = encrypt_filename(&keys.primary, &in_pics, "todo.txt").unwrap();
    assert_ne!(cipher_docs, cipher_pics);
    assert_ne!(in_docs, in_pics);

    assert_ne!(
        layout::cipher_dir(root, in_docs.as_str()),
        layout::cipher_dir(root, in_pics.as_str())
    );
}

#[test]
fn a_moved_folder_is_indistinguishable_from_a_new_one() {
    // Deriving a child id folds in the parent, so the same folder name under a
    // different parent produces an unrelated id — which is exactly why the server
    // cannot tell a rename or move from a fresh create.
    let keys = MasterKeys::generate().unwrap();
    let under_a = dir_id_for(&keys.hmac, &keys.primary, &["top", "shared"]);
    let under_b = dir_id_for(&keys.hmac, &keys.primary, &["other", "shared"]);
    assert_ne!(under_a, under_b);
}

#[test]
fn every_directory_has_a_sharded_marker_path() {
    let keys = MasterKeys::generate().unwrap();
    let root = Path::new("/vault");
    let id = dir_id_for(&keys.hmac, &keys.primary, &["Documents"]);
    let marker = layout::marker_path(root, id.as_str());
    // Markers live under `d/`, sharded by the first characters of the id.
    assert!(marker.starts_with(root.join("d")));
    assert!(marker.to_str().unwrap().ends_with(".c9r"));
}
