//! Wrapping the master keys under the password-derived key-encryption key.
//!
//! `vault.json` never holds a master key in the clear. Both are encrypted under a
//! [`Kek`] derived from the user's password, and the header carries a MAC over its
//! own bytes so that a wrong password is caught before anything is decrypted. This
//! module is the whole of that ceremony, and it is pure: it takes bytes and returns
//! bytes, so the exact same code can produce a vault on desktop and verify one on a
//! phone.
//!
//! ## Why one nonce is safe here
//!
//! `docs/format.md` records a single wrap nonce for both master keys. Reusing a nonce
//! under the *same* AES-GCM key is a catastrophic mistake, so the two keys are not
//! encrypted under the same key: the primary and HMAC keys are sealed under separate
//! subkeys derived from the KEK with distinct labels. A single nonce reused across
//! *different* keys is harmless, which is what makes the header one nonce smaller.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use crate::derive::{hkdf_sha256, hmac_sha256};
use crate::error::{CryptoError, Result};
use crate::kdf::Kek;
use crate::keys::{MasterKey, MasterKeys, MASTER_KEY_LEN};

/// Length a GCM nonce must be for the wrap and MAC operations.
pub const GCM_NONCE_LEN: usize = 12;

/// Encrypts both master keys under `kek`, returning `(wrappedPrimary, wrappedHmac)`
/// as the raw bytes the header stores (each 32-byte key plus a 16-byte tag).
///
/// `nonce` must be [`GCM_NONCE_LEN`] bytes and fresh per vault; it is stored in the
/// header next to the ciphertext it protects.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidInput`] for a wrong-length nonce and
/// [`CryptoError::Backend`] if AES-GCM refuses to run.
pub fn wrap_master_keys(kek: &Kek, keys: &MasterKeys, nonce: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = wrap_nonce(nonce)?;
    let primary = seal_subkey(kek, b"kwrap-primary", nonce, keys.primary.as_bytes())?;
    let hmac = seal_subkey(kek, b"kwrap-hmac", nonce, keys.hmac.as_bytes())?;
    Ok((primary, hmac))
}

/// Recovers the master keys from their wrapped form.
///
/// # Errors
///
/// Returns [`CryptoError::KeyAuth`] if either wrapped key does not authenticate,
/// which means the password was wrong or `vault.json` was tampered with. (In the
/// normal open flow the header MAC has already rejected such a vault, so this is a
/// second line of defence rather than the first.)
pub fn unwrap_master_keys(
    kek: &Kek,
    nonce: &[u8],
    wrapped_primary: &[u8],
    wrapped_hmac: &[u8],
) -> Result<MasterKeys> {
    let nonce = wrap_nonce(nonce)?;
    let primary = open_subkey(kek, b"kwrap-primary", nonce, wrapped_primary)?;
    let hmac = open_subkey(kek, b"kwrap-hmac", nonce, wrapped_hmac)?;
    Ok(MasterKeys {
        primary: MasterKey::from_bytes(&primary)?,
        hmac: MasterKey::from_bytes(&hmac)?,
    })
}

/// The header's `versionMac`: HMAC-SHA256 over a caller-canonical rendering of the
/// header fields, under a MAC subkey derived from `kek`.
///
/// The canonical bytes are the caller's responsibility (they know the header's
/// field layout); this function only fixes the key. A wrong password yields a
/// different `kek`, hence a different MAC, so comparison rejects it without
/// touching the wrapped keys.
///
/// # Errors
///
/// Propagates [`CryptoError::Backend`] from HKDF or HMAC.
pub fn header_mac(kek: &Kek, canonical_header: &[u8]) -> Result<Vec<u8>> {
    let key = hkdf_sha256(kek.as_bytes(), b"header-mac", 32)?;
    hmac_sha256(&key, canonical_header)
}

fn wrap_nonce(nonce: &[u8]) -> Result<&[u8; GCM_NONCE_LEN]> {
    nonce
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("wrap nonce is not 12 bytes"))
}

/// Seals one 32-byte key under a subkey of `kek` named by `label`.
fn seal_subkey(
    kek: &Kek,
    label: &[u8],
    nonce: &[u8],
    key: &[u8; MASTER_KEY_LEN],
) -> Result<Vec<u8>> {
    let cipher = cipher_for_subkey(kek, label)?;
    cipher
        .encrypt(Nonce::from_slice(nonce), key.as_slice())
        .map_err(|_| CryptoError::Backend("key wrapping failed"))
}

fn open_subkey(kek: &Kek, label: &[u8], nonce: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
    let cipher = cipher_for_subkey(kek, label)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), sealed)
        .map_err(|_| CryptoError::KeyAuth)
}

fn cipher_for_subkey(kek: &Kek, label: &[u8]) -> Result<Aes256Gcm> {
    let subkey = hkdf_sha256(kek.as_bytes(), label, 32)?;
    Aes256Gcm::new_from_slice(&subkey).map_err(|_| CryptoError::Backend("wrap subkey length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> Kek {
        Kek::from_bytes(vec![0x5a; 32])
    }

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[1; MASTER_KEY_LEN]).unwrap(),
            hmac: MasterKey::from_bytes(&[2; MASTER_KEY_LEN]).unwrap(),
        }
    }

    const NONCE: &[u8] = b"nonce12bytes";

    #[test]
    fn wrap_then_unwrap_recovers_the_keys() {
        let (wp, wh) = wrap_master_keys(&kek(), &keys(), NONCE).unwrap();
        assert_eq!(wp.len(), MASTER_KEY_LEN + 16);
        assert_eq!(wh.len(), MASTER_KEY_LEN + 16);
        let back = unwrap_master_keys(&kek(), NONCE, &wp, &wh).unwrap();
        assert_eq!(back.primary.as_bytes(), keys().primary.as_bytes());
        assert_eq!(back.hmac.as_bytes(), keys().hmac.as_bytes());
    }

    #[test]
    fn the_two_wrapped_keys_differ_despite_one_nonce() {
        // The proof the header's "one nonce" is safe: under distinct subkeys, the
        // same nonce on the same plaintext would still give distinct ciphertexts.
        let keys = MasterKeys {
            primary: MasterKey::from_bytes(&[9; MASTER_KEY_LEN]).unwrap(),
            hmac: MasterKey::from_bytes(&[9; MASTER_KEY_LEN]).unwrap(),
        };
        let (wp, wh) = wrap_master_keys(&kek(), &keys, NONCE).unwrap();
        assert_ne!(wp, wh);
    }

    #[test]
    fn wrong_kek_cannot_unwrap() {
        let (wp, wh) = wrap_master_keys(&kek(), &keys(), NONCE).unwrap();
        let other = Kek::from_bytes(vec![0x5b; 32]);
        assert!(matches!(
            unwrap_master_keys(&other, NONCE, &wp, &wh),
            Err(CryptoError::KeyAuth)
        ));
    }

    #[test]
    fn tampered_wrapped_key_is_rejected() {
        let (mut wp, wh) = wrap_master_keys(&kek(), &keys(), NONCE).unwrap();
        let last = wp.len() - 1;
        wp[last] ^= 0x80;
        assert!(matches!(
            unwrap_master_keys(&kek(), NONCE, &wp, &wh),
            Err(CryptoError::KeyAuth)
        ));
    }

    #[test]
    fn a_bad_nonce_length_is_input_invalid() {
        assert!(matches!(
            wrap_master_keys(&kek(), &keys(), b"short"),
            Err(CryptoError::InvalidInput(_))
        ));
    }

    #[test]
    fn header_mac_is_key_and_content_dependent() {
        let m = header_mac(&kek(), b"header-bytes").unwrap();
        assert_eq!(m.len(), 32);
        assert_eq!(m, header_mac(&kek(), b"header-bytes").unwrap());
        assert_ne!(m, header_mac(&kek(), b"header-byte0").unwrap());
        assert_ne!(
            m,
            header_mac(&Kek::from_bytes(vec![0x5b; 32]), b"header-bytes").unwrap()
        );
    }
}
