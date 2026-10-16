//! Pins the test vectors published in `docs/format.md`. These are the values any
//! independent implementation must reproduce; if a change here alters one of them,
//! it is a breaking format change and the document must move with it.

use syncbox_crypto::content::{chunk_id, open_chunk, seal_chunk};
use syncbox_crypto::file::{encode_manifest, file_key, ChunkEntry, Manifest};
use syncbox_crypto::kdf::{derive_kek, Algorithm, Params};
use syncbox_crypto::keys::{MasterKey, MasterKeys};
use syncbox_crypto::names::{decrypt_filename, encrypt_filename, DirId};
use syncbox_crypto::wrap::{header_mac, unwrap_master_keys, wrap_master_keys};
use syncbox_crypto::Kek;

fn by_range(start: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = start + i as u8;
    }
    out
}

fn by_start_len(start: u8, len: usize) -> Vec<u8> {
    (0..len as u8).map(|i| start + i).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_key() -> MasterKey {
    MasterKey::from_bytes(&by_range(0x00)).unwrap()
}
fn primary_key() -> MasterKey {
    MasterKey::from_bytes(&by_range(0x20)).unwrap()
}

#[test]
fn kdf_vector() {
    let params = Params {
        algorithm: Algorithm::Argon2id,
        memory_kib: 64,
        iterations: 2,
        parallelism: 1,
        output_len: 32,
    };
    let salt = by_start_len(0xAA, 16);
    let kek = derive_kek("correct horse battery staple", &salt, &params).unwrap();
    assert_eq!(
        hex(kek.as_bytes()),
        "6fcf49613105db37e8238aa39a57a358bae0ff7cf4dc127361d787987a87fe60"
    );
}

#[test]
fn root_dir_id_vector() {
    let root = DirId::root(&hmac_key()).unwrap();
    assert_eq!(
        root.as_str(),
        "TE5M42BDG3T5Z0KB8JMXAR3XWWJ9D90NTFTA3A68HRXVKPMDR75G"
    );
}

#[test]
fn filename_vector() {
    let root = DirId::root(&hmac_key()).unwrap();
    let cipher = encrypt_filename(&primary_key(), &root, "meeting notes.txt").unwrap();
    assert_eq!(
        cipher,
        "VQAF7BFK7Y9BACY4PNNH5NB4XS0C4DKDCRT15NVNF4Q9ZFE6FTVPP"
    );
    // And it decrypts back, proving the vector is a genuine round trip.
    assert_eq!(
        decrypt_filename(&primary_key(), &root, &cipher).unwrap(),
        "meeting notes.txt"
    );
}

#[test]
fn chunk_id_vector() {
    let id = chunk_id(&hmac_key(), b"hello world").unwrap();
    assert_eq!(
        id.as_str(),
        "84DSMMF8ASF1ZHWP8ESADH375X53RFJQ7GSX16AT11T8SDGJHT70"
    );
}

#[test]
fn chunk_encryption_vector() {
    // Content-derived: key and nonce come from the primary master key and the
    // chunk's own id, so the stored blob is a pure function of the content.
    let (id, stored) = seal_chunk(&primary_key(), &hmac_key(), b"Syncbox").unwrap();
    assert_eq!(
        id.as_str(),
        "XDFTTNGJ44MV0AYW06AFJP528XYNR5S60PVTYCRYSZZYSZ6DTP30"
    );
    assert_eq!(
        hex(&stored),
        "3115ec4ba4640ede4b15a0674666b9edf3e5582bd37de795c493fffa029627e7706eeb"
    );
    assert_eq!(
        open_chunk(&primary_key(), &id, &stored).unwrap(),
        b"Syncbox"
    );
}

#[test]
fn file_key_and_manifest_vectors() {
    // Rebuild the manifest exactly as `examples/vectors.rs` does: two chunks and
    // their total plaintext size, encrypted under the file key for the root
    // directory and the encrypted filename "meeting notes.txt".
    let root = DirId::root(&hmac_key()).unwrap();
    let cipher_name = encrypt_filename(&primary_key(), &root, "meeting notes.txt").unwrap();

    let first = seal_chunk(&primary_key(), &hmac_key(), b"Syncbox").unwrap();
    let second = seal_chunk(&primary_key(), &hmac_key(), b"hello world").unwrap();
    let manifest = Manifest {
        plaintext_size: (first.1.len() - 28 + second.1.len() - 28) as u64,
        chunks: vec![
            ChunkEntry {
                id: first.0,
                stored_len: first.1.len() as u32,
            },
            ChunkEntry {
                id: second.0,
                stored_len: second.1.len() as u32,
            },
        ],
    };

    assert_eq!(
        hex(&file_key(&primary_key(), &root, &cipher_name).unwrap()),
        "01bbcfa1fb3cf263496811353b48446669f7b70a2f71022f90f6b4dbea9f36ca"
    );
    assert_eq!(
        hex(&encode_manifest(&primary_key(), &root, &cipher_name, &manifest).unwrap()),
        "2ba4f471adb5f9fa5fc8890d2a8e076aae8f1258b1a9356d8b8a1ed70d954c5bc8c3d591e74c4bdd2f918f86dac2809cd4067c7c2bd0ebbef1949bac6bd2503c362d3388d3eed42dc3663f5788d208754fd4f86de2497884d0b01e5f7ee1847497f171bb601d75efbcf0d55a82dfc8df61da04308555ff2da5aae9fde3456dab659e15a1c18398c8fbfcf31a62ea240b628a4af5f21faec858f7a8d5cf70d8dc4400cb554ee66e31893a27c09b312468848436fa40a78d022110490e9e44f9be7293a393ba16"
    );
}

#[test]
fn key_wrap_and_header_mac_vectors() {
    let wrap_kek = Kek::from_bytes(by_range(0x11).to_vec());
    let keys = MasterKeys {
        primary: primary_key(),
        hmac: hmac_key(),
    };
    let nonce = by_start_len(0x01, 12);
    let (wp, wh) = wrap_master_keys(&wrap_kek, &keys, &nonce).unwrap();
    assert_eq!(
        hex(&wp),
        "fe1f126aa658a4192778d0abbce43ece743b5a78fac863d4aa9b4c3e6e62a5e7d64f88f14ffdf10ce03f1a068b492f1f"
    );
    assert_eq!(
        hex(&wh),
        "6847b0bca24d844cc947156168b88a8a01b56d3a5bda3a79b5f058babe0a011117976c7a6b794b8ae32e9656517ebb71"
    );
    // Round-trips back to the same keys.
    let back = unwrap_master_keys(&wrap_kek, &nonce, &wp, &wh).unwrap();
    assert_eq!(back.primary.as_bytes(), primary_key().as_bytes());
    assert_eq!(back.hmac.as_bytes(), hmac_key().as_bytes());

    assert_eq!(
        hex(&header_mac(&wrap_kek, b"header").unwrap()),
        "42e0418e6620af50655becdd070e3a0171c9aa81f12eb1010ceb2616b244d655"
    );
}
