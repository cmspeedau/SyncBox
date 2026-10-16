//! Key-derivation helpers shared by the rest of the crate.
//!
//! Two primitives do all the "derive a key for a specific job" work in Syncbox:
//! HKDF-SHA256 for turning one secret into the many per-directory, per-chunk, and
//! per-purpose keys the format needs, and HMAC-SHA256 for the ids that must be
//! deterministic but unforgeable. Both live here so the domain-separation labels
//! are written down once and cannot drift between the modules that use them.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{CryptoError, Result};

/// HKDF-SHA256 with an empty salt, expanding `ikm` under a domain-separation
/// `info` string to `len` bytes.
///
/// The empty salt is deliberate: these derivations already bind a per-vault secret
/// (a master key) and a per-job label, so a salt would add nothing, and leaving it
/// out keeps every implementation in agreement about the exact bytes.
pub(crate) fn hkdf_sha256(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = vec![0u8; len];
    hkdf.expand(info, &mut okm)
        .map_err(|_| CryptoError::Backend("HKDF output length out of range"))?;
    Ok(okm)
}

/// HMAC-SHA256 of `msg` under `key`.
///
/// `key` is any length (HMAC pre-hashes long keys), but callers pass the fixed
/// 32-byte master keys, so the `new_from_slice` failure is unreachable in practice;
/// it is still mapped rather than unwrapped so a bad caller cannot panic the crate.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| CryptoError::Backend("HMAC key could not be accepted"))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_is_deterministic_and_length_exact() {
        let a = hkdf_sha256(b"ikm", b"info", 64).unwrap();
        let b = hkdf_sha256(b"ikm", b"info", 64).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        // A different label must give a different key: this is the property every
        // per-purpose derivation in the format leans on.
        assert_ne!(a, hkdf_sha256(b"ikm", b"other", 64).unwrap());
    }

    #[test]
    fn hkdf_rejects_an_impossible_length() {
        // HKDF-SHA256 can produce at most 255 * 32 bytes.
        assert!(matches!(
            hkdf_sha256(b"ikm", b"info", 255 * 32 + 1),
            Err(CryptoError::Backend(_))
        ));
    }

    #[test]
    fn hmac_is_deterministic_and_key_dependent() {
        let m = hmac_sha256(b"key-a", b"msg").unwrap();
        assert_eq!(m.len(), 32);
        assert_eq!(m, hmac_sha256(b"key-a", b"msg").unwrap());
        assert_ne!(m, hmac_sha256(b"key-b", b"msg").unwrap());
    }
}
