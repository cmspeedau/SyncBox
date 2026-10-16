//! Prints the fixed test vectors that `docs/format.md` records. Every value here
//! is derived only from the fixed inputs below, so any conforming implementation —
//! in any language — that reproduces these outputs is doing Syncbox's crypto right.
//!
//! Run with `cargo run --example vectors -p syncbox-crypto`. The `test_vectors`
//! test in the crate asserts these same numbers, so the document cannot silently
//! drift from the code.

use syncbox_crypto::content::{chunk_id, seal_chunk};
use syncbox_crypto::file::{encode_manifest, file_key, ChunkEntry, Manifest};
use syncbox_crypto::kdf::{derive_kek, Algorithm, Params};
use syncbox_crypto::keys::{MasterKey, MasterKeys};
use syncbox_crypto::names::{base32_encode, encrypt_filename, DirId};
use syncbox_crypto::wrap::{header_mac, wrap_master_keys};

/// `hmacMasterKey`: bytes `0x00 ..= 0x1f`.
fn hmac_key() -> MasterKey {
    MasterKey::from_bytes(&by_range(0x00)).unwrap()
}

/// `primaryMasterKey`: bytes `0x20 ..= 0x3f`.
fn primary_key() -> MasterKey {
    MasterKey::from_bytes(&by_range(0x20)).unwrap()
}

fn by_range(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = start + i as u8;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    // 1. Key derivation: a deliberately cheap Argon2id parameter set so the vector
    //    is quick to recompute by hand.
    let kdf_params = Params {
        algorithm: Algorithm::Argon2id,
        memory_kib: 64,
        iterations: 2,
        parallelism: 1,
        output_len: 32,
    };
    let salt = by_start_len(0xAA, 16);
    let kek = derive_kek("correct horse battery staple", &salt, &kdf_params).unwrap();
    println!("kek            = {}", hex(kek.as_bytes()));

    // 2. Root directory id under the hmac master key.
    let root = DirId::root(&hmac_key()).unwrap();
    println!("root_dir_id    = {}", root.as_str());

    // 3. A filename encrypted for the root directory (AES-SIV, deterministic).
    let cipher_name = encrypt_filename(&primary_key(), &root, "meeting notes.txt").unwrap();
    println!("enc_filename   = {}", cipher_name);

    // 4. Chunk id: HMAC over plaintext under the hmac master key.
    let id = chunk_id(&hmac_key(), b"hello world").unwrap();
    println!("chunk_id       = {}", id.as_str());

    // 5. Content-derived chunk sealing. The key and nonce come from the primary
    //    master key and the chunk's own id, so the whole stored blob is a function
    //    of the content: the same plaintext chunk is the same bytes everywhere.
    let (sync_id, stored) = seal_chunk(&primary_key(), &hmac_key(), b"Syncbox").unwrap();
    println!("chunk2_id      = {}", sync_id.as_str());
    println!("stored_chunk   = {}", hex(&stored));

    // 6. A per-file manifest, encrypted under a per-file key derived from the file's
    //    identity (the root directory and the encrypted filename from vector 3).
    let second = seal_chunk(&primary_key(), &hmac_key(), b"hello world").unwrap();
    let manifest = Manifest {
        plaintext_size: (stored.len() - 28 + second.1.len() - 28) as u64,
        chunks: vec![
            ChunkEntry {
                id: sync_id,
                stored_len: stored.len() as u32,
            },
            ChunkEntry {
                id: second.0,
                stored_len: second.1.len() as u32,
            },
        ],
    };
    println!(
        "file_key       = {}",
        hex(&file_key(&primary_key(), &root, &cipher_name).unwrap())
    );
    println!(
        "manifest       = {}",
        hex(&encode_manifest(&primary_key(), &root, &cipher_name, &manifest).unwrap())
    );

    // 7/8. Key wrapping and the header MAC, under a fixed KEK and nonce.
    let wrap_kek = syncbox_crypto::Kek::from_bytes(by_range(0x11).to_vec());
    let keys = MasterKeys {
        primary: primary_key(),
        hmac: hmac_key(),
    };
    let nonce = by_start_len(0x01, 12);
    let (wp, wh) = wrap_master_keys(&wrap_kek, &keys, &nonce).unwrap();
    println!("wrapped_primary = {}", hex(&wp));
    println!("wrapped_hmac    = {}", hex(&wh));
    println!(
        "header_mac      = {}",
        hex(&header_mac(&wrap_kek, b"header").unwrap())
    );

    // Echo base32 of a known value so the alphabet itself is pinned.
    println!("base32_0x00     = {}", base32_encode(&[0x00]));
}

fn by_start_len(start: u8, len: usize) -> Vec<u8> {
    (0..len as u8).map(|i| start + i).collect()
}
