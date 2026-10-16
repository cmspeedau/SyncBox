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

use crate::error::{CryptoError, Result};

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
    /// The id of the vault root, the HMAC of the empty string.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Unimplemented`] until M1 adds HMAC-SHA256.
    pub fn root() -> Result<Self> {
        Err(CryptoError::Unimplemented("root directory id"))
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

/// Derives a child directory id from its parent and encrypted name.
///
/// # Errors
///
/// Returns [`CryptoError::Unimplemented`] until M1 adds HMAC-SHA256.
pub fn child_dir_id(parent: &DirId, encrypted_name: &str) -> Result<DirId> {
    let _ = (parent, encrypted_name);
    Err(CryptoError::Unimplemented("directory id derivation"))
}

/// Encrypts one filename for the directory it lives in.
///
/// # Errors
///
/// Returns [`CryptoError::Unimplemented`] until M1 adds AES-SIV.
pub fn encrypt_filename(dir: &DirId, name: &str) -> Result<String> {
    let _ = (dir, name);
    Err(CryptoError::Unimplemented("AES-SIV filename encryption"))
}

/// Decrypts one filename from the directory it lives in.
///
/// # Errors
///
/// Returns [`CryptoError::Unimplemented`] until M1 adds AES-SIV.
pub fn decrypt_filename(dir: &DirId, cipher_name: &str) -> Result<String> {
    let _ = (dir, cipher_name);
    Err(CryptoError::Unimplemented("AES-SIV filename decryption"))
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
    fn unimplemented_name_operations_say_so() {
        let dir = DirId::from_base32("AA");
        assert!(dir_id_is_unimplemented());
        assert!(matches!(
            encrypt_filename(&dir, "notes.txt"),
            Err(CryptoError::Unimplemented(_))
        ));
    }

    fn dir_id_is_unimplemented() -> bool {
        matches!(DirId::root(), Err(CryptoError::Unimplemented(_)))
    }
}
