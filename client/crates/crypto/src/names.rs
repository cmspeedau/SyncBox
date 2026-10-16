//! Encrypted filenames and directory ids.
//!
//! The scheme is Cryptomator's. A directory has an id, which is an HMAC over its
//! parent's id plus its own encrypted name. A filename is AES-SIV encrypted with
//! a key derived for the directory it lives in, base32 encoded, and stored under
//! a `.c9r` suffix. Because every name is keyed by its directory id, the same
//! filename in two directories produces two unrelated ciphertexts, and the
//! server cannot tell that a folder was merely renamed.
//!
//! The tree itself is reconstructed from empty marker files under
//! [`DIR_MARKER_DIR`], so a client can rediscover directories without decrypting
//! any content.

use crate::derive::{hkdf_sha256, hmac_sha256};
use crate::error::{CryptoError, Result};
use crate::keys::MasterKey;
use aes_siv::{siv::Aes256Siv, KeyInit};

/// Suffix on every encrypted file.
pub const FILE_SUFFIX: &str = ".c9r";

/// Suffix on the directory that holds an over-long encrypted name.
pub const LONG_NAME_SUFFIX: &str = ".c9s";

/// Directory holding the empty marker files that reconstruct the tree.
pub const DIR_MARKER_DIR: &str = "d";

/// Crockford base32 alphabet, which omits I, L, O and U so transcribed ids stay
/// unambiguous.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A directory id: the HMAC that names a directory in the ciphertext tree.
///
/// Stored as uppercase Crockford base32.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirId(String);

impl DirId {
    /// The id of the vault root: the HMAC of the empty string under the vault's
    /// `hmacMasterKey`. Every other id is derived from this one.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Backend`] if HMAC rejects the key length, which the
    /// 32-byte master key never triggers.
    pub fn root(hmac_key: &MasterKey) -> Result<Self> {
        Ok(Self(base32_encode(&hmac_sha256(hmac_key.as_bytes(), b"")?)))
    }

    /// Wraps an id that is already encoded.
    #[must_use]
    pub fn from_base32(text: &str) -> Self {
        Self(text.to_ascii_uppercase())
    }

    /// The encoded id, as it appears in a path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DirId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Encodes bytes as Crockford base32, without padding.
///
/// Any leftover bits are left-shifted into a final symbol, matching how
/// Cryptomator's encoder pads, so decoding a length that is not a multiple of
/// five bytes discards only those padding bits.
#[must_use]
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + bytes.len() / 2 + 1);
    let mut acc: u32 = 0;
    let mut held = 0u32;

    for &byte in bytes {
        acc = (acc << 8) | u32::from(byte);
        held += 8;
        while held >= 5 {
            held -= 5;
            let index = usize::try_from((acc >> held) & 0x1F).unwrap_or(0);
            out.push(char::from(CROCKFORD[index]));
            acc &= (1 << held) - 1;
        }
    }

    if held > 0 {
        let index = usize::try_from((acc << (5 - held)) & 0x1F).unwrap_or(0);
        out.push(char::from(CROCKFORD[index]));
    }

    out
}

/// Decodes Crockford base32, accepting padding and either case.
///
/// `I` and `L` are read as `1`, and `U` as `V`, which is Crockford's tolerance
/// rule for handwriting.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] if the text holds a character outside
/// the alphabet.
pub fn base32_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 8 * 5 + 5);
    let mut acc: u32 = 0;
    let mut held = 0u32;

    for ch in text.chars() {
        if ch == '=' || ch == '-' {
            continue;
        }
        let value = symbol_value(ch)?;
        acc = (acc << 5) | u32::from(value);
        held += 5;
        if held >= 8 {
            held -= 8;
            let byte = u8::try_from((acc >> held) & 0xFF).unwrap_or(0);
            out.push(byte);
            acc &= (1 << held) - 1;
        }
    }

    if held >= 5 {
        return Err(CryptoError::InvalidInput(
            "trailing base32 symbol carries no whole byte",
        ));
    }

    Ok(out)
}

/// Maps one Crockford symbol to its five-bit value.
fn symbol_value(ch: char) -> Result<u8> {
    let up = ch.to_ascii_uppercase();
    let tolerant = match up {
        'I' | 'L' => '1',
        'U' => 'V',
        other => other,
    };
    CROCKFORD
        .iter()
        .position(|&symbol| symbol == tolerant as u8)
        .map(|position| position as u8)
        .ok_or(CryptoError::InvalidInput(
            "character outside the base32 alphabet",
        ))
}

/// Derives a child directory id from its parent's id and the child's encrypted
/// name, per `docs/format.md`:
///
/// ```text
/// BASE32( HMAC-SHA256( hmacMasterKey, parent || "\n" || encryptedName ) )
/// ```
///
/// Folding the parent in is what makes a rename or move anywhere in the tree
/// re-key everything beneath it, so the server cannot tell a folder was moved.
///
/// # Errors
///
/// Propagates [`CryptoError::Backend`] from HMAC.
pub fn child_dir_id(hmac_key: &MasterKey, parent: &DirId, encrypted_name: &str) -> Result<DirId> {
    let mut message = Vec::with_capacity(parent.as_str().len() + 1 + encrypted_name.len());
    message.extend_from_slice(parent.as_str().as_bytes());
    message.push(b'\n');
    message.extend_from_slice(encrypted_name.as_bytes());
    Ok(DirId(base32_encode(&hmac_sha256(
        hmac_key.as_bytes(),
        &message,
    )?)))
}

/// The AES-SIV key a filename in `dir` is encrypted under:
/// `HKDF(primaryMasterKey, "siv" || dirId)`, 64 bytes (two AES-256 halves).
fn filename_key(primary_key: &MasterKey, dir: &DirId) -> Result<Vec<u8>> {
    let mut info = b"siv".to_vec();
    info.extend_from_slice(dir.as_str().as_bytes());
    hkdf_sha256(primary_key.as_bytes(), &info, 64)
}

/// Encrypts one filename for the directory it lives in, returning the base32
/// ciphertext (without the `.c9r` suffix the layout adds).
///
/// The directory id is both the key-derivation input and the associated data, so
/// the same name in two directories gives unrelated ciphertexts, and a ciphertext
/// name cannot be moved between directories without failing to decrypt.
///
/// # Errors
///
/// Returns [`CryptoError::Backend`] if AES-SIV rejects the derived key length.
pub fn encrypt_filename(primary_key: &MasterKey, dir: &DirId, name: &str) -> Result<String> {
    let key = filename_key(primary_key, dir)?;
    let mut siv =
        Aes256Siv::new_from_slice(&key).map_err(|_| CryptoError::Backend("AES-SIV key length"))?;
    let associated_data = dir.as_str().as_bytes();
    let ciphertext = siv
        .encrypt([associated_data], name.as_bytes())
        .map_err(|_| CryptoError::Backend("AES-SIV encryption failed"))?;
    Ok(base32_encode(&ciphertext))
}

/// Decrypts one filename from the directory it claims to live in.
///
/// # Errors
///
/// Returns [`CryptoError::KeyAuth`] when the name did not authenticate — it was
/// made for a different directory, or tampered with — and
/// [`CryptoError::InvalidInput`] if it is not valid base32.
pub fn decrypt_filename(primary_key: &MasterKey, dir: &DirId, cipher_name: &str) -> Result<String> {
    let key = filename_key(primary_key, dir)?;
    let mut siv =
        Aes256Siv::new_from_slice(&key).map_err(|_| CryptoError::Backend("AES-SIV key length"))?;
    let associated_data = dir.as_str().as_bytes();
    let ciphertext = base32_decode(cipher_name)?;
    let plaintext = siv
        .decrypt([associated_data], &ciphertext)
        .map_err(|_| CryptoError::KeyAuth)?;
    String::from_utf8(plaintext).map_err(|_| CryptoError::KeyAuth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_known_single_byte_values() {
        assert_eq!(base32_encode(&[0x00]), "00");
        assert_eq!(base32_encode(&[0xFF]), "ZW");
        assert_eq!(base32_encode(&[]), "");
    }

    #[test]
    fn base32_round_trips_every_length_up_to_sixteen() {
        // Encoded lengths are not multiples of eight bits, so each extra input
        // byte exercises a different amount of padding in the final symbol.
        for len in 0..=16usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let encoded = base32_encode(&bytes);
            let decoded = base32_decode(&encoded).expect("encoder only emits valid symbols");
            assert_eq!(decoded, bytes, "round trip failed for {len} bytes");
        }
    }

    #[test]
    fn base32_decode_is_case_insensitive_and_tolerant() {
        assert_eq!(base32_decode("zw").unwrap(), base32_decode("ZW").unwrap());
        assert_eq!(base32_decode("ZW=").unwrap(), vec![0xFF]);
        // `1` is a real symbol, and the tolerated look-alikes must not collide
        // with it.
        assert_eq!(base32_decode("11").unwrap(), base32_decode("II").unwrap());
    }

    #[test]
    fn base32_rejects_characters_outside_the_alphabet() {
        let err = base32_decode("0!*").expect_err("not base32");
        assert!(matches!(err, CryptoError::InvalidInput(_)));
    }

    #[test]
    fn directory_ids_are_uppercased_and_comparable() {
        let id = DirId::from_base32("abcdefgh");
        assert_eq!(id.as_str(), "ABCDEFGH");
        assert_eq!(id.to_string(), "ABCDEFGH");
    }

    #[test]
    fn root_dir_id_is_deterministic_and_key_dependent() {
        let key = MasterKey::from_bytes(&[7u8; 32]).unwrap();
        let other = MasterKey::from_bytes(&[8u8; 32]).unwrap();
        let root = DirId::root(&key).unwrap();
        assert_eq!(root.as_str(), DirId::root(&key).unwrap().as_str());
        assert_eq!(root.to_string(), root.as_str());
        assert_ne!(root, DirId::root(&other).unwrap());
    }

    #[test]
    fn filename_round_trips_within_its_directory() {
        let primary = MasterKey::from_bytes(&[1u8; 32]).unwrap();
        let dir = DirId::from_base32("ABCDEFGHIJKM");
        for name in ["notes.txt", "a", "résumé – naïve.txt", "tabs\tand spaces"] {
            let cipher = encrypt_filename(&primary, &dir, name).unwrap();
            assert!(
                cipher == cipher.to_ascii_uppercase(),
                "encoded name must be uppercase base32"
            );
            assert_eq!(decrypt_filename(&primary, &dir, &cipher).unwrap(), name);
        }
    }

    #[test]
    fn the_same_name_in_two_directories_gives_unrelated_ciphertext() {
        let primary = MasterKey::from_bytes(&[1u8; 32]).unwrap();
        let dir_a = DirId::from_base32("AAAAAAAAAAAA");
        let dir_b = DirId::from_base32("BBBBBBBBBBBB");
        let in_a = encrypt_filename(&primary, &dir_a, "secret.txt").unwrap();
        let in_b = encrypt_filename(&primary, &dir_b, "secret.txt").unwrap();
        assert_ne!(in_a, in_b);
        // A name made for one directory must not decrypt in another: the directory
        // id is associated data, so the tag fails.
        assert!(matches!(
            decrypt_filename(&primary, &dir_b, &in_a),
            Err(CryptoError::KeyAuth)
        ));
    }

    #[test]
    fn child_dir_id_depends_on_both_parent_and_name() {
        let hmac = MasterKey::from_bytes(&[9u8; 32]).unwrap();
        let parent = DirId::root(&hmac).unwrap();
        let child = child_dir_id(&hmac, &parent, "SOMEENCNAME").unwrap();
        assert_eq!(child, child_dir_id(&hmac, &parent, "SOMEENCNAME").unwrap());
        // Changing the parent or the name changes the id entirely.
        assert_ne!(child, child_dir_id(&hmac, &parent, "OTHERENAME").unwrap());
        let other_parent = DirId::from_base32("ZZZZZZZZZZZZ");
        assert_ne!(
            child,
            child_dir_id(&hmac, &other_parent, "SOMEENCNAME").unwrap()
        );
    }

    #[test]
    fn decrypting_a_non_base32_name_is_input_invalid() {
        let primary = MasterKey::from_bytes(&[1u8; 32]).unwrap();
        let dir = DirId::from_base32("ABCDEFGHIJKM");
        assert!(matches!(
            decrypt_filename(&primary, &dir, "not base32!!"),
            Err(CryptoError::InvalidInput(_))
        ));
    }
}
