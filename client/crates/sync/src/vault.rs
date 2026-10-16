//! The file-level codec: a plaintext file in, the vault's encrypted form out.
//!
//! [`Vault`] is the key-holding context the [`crate::Engine`] works in. It knows
//! how to name things the way the vault names them (a directory id chained down
//! from the root, a filename encrypted for its directory) and how to turn a
//! buffer of plaintext into the pair the server stores — content-addressed chunks
//! plus an authenticated manifest — and back again.
//!
//! It deliberately knows nothing about servers or sockets: chunk bytes are handed
//! to the caller to upload, and on the way back they are pulled through a `fetch`
//! closure the caller supplies. That keeps every decision here pure enough to
//! unit-test without a network, and lets the engine own the interaction with
//! [`syncbox_transport`].
//!
//! The chunk keying is content-derived (see [`crate::chunker`] and
//! `docs/format.md`), so [`Vault::seal`] turns the same bytes into the same chunk
//! ids and ciphertext regardless of which file or position they came from — which
//! is exactly what lets the server store a chunk once and a delta upload skip
//! everything an edit left untouched.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use syncbox_crypto::names::{child_dir_id, decrypt_filename, encrypt_filename, DirId};
use syncbox_crypto::{
    decode_manifest, encode_manifest, open_chunk, seal_chunk, ChunkEntry, ChunkId, Manifest,
    MasterKeys,
};

use crate::chunker::Chunker;
use crate::chunker::FastCdc;
use crate::error::{Result, SyncError};

/// The encrypted result of sealing one file.
#[derive(Debug)]
pub struct Sealed {
    /// The authenticated manifest bytes, ready to base64 into a revision.
    pub manifest: Vec<u8>,
    /// Chunk ids in file order (with repeats, matching the manifest).
    pub chunk_ids: Vec<ChunkId>,
    /// The distinct chunks, as id and stored bytes, to offer the server. The
    /// caller uploads only those it reports missing.
    pub chunks: Vec<(ChunkId, Vec<u8>)>,
    /// Plaintext byte count, carried to the revision's `size`.
    pub plaintext_size: u64,
}

/// One unlocked vault: its keys, its root directory id, and where its plaintext
/// tree sits on disk.
pub struct Vault {
    keys: MasterKeys,
    root: DirId,
    plaintext_root: PathBuf,
    vault_id: String,
}

// Keys are secret material; the derived Debug would put them in a log. Debug only
// the non-sensitive coordinates.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("root", &self.root)
            .field("plaintext_root", &self.plaintext_root)
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Wraps unlocked `keys` for the vault the server knows as `vault_id`, whose
    /// readable files live under `plaintext_root`.
    ///
    /// # Errors
    ///
    /// Propagates a crypto error if the root directory id cannot be derived.
    pub fn new(
        keys: MasterKeys,
        vault_id: impl Into<String>,
        plaintext_root: impl Into<PathBuf>,
    ) -> Result<Self> {
        let root = DirId::root(&keys.hmac)?;
        Ok(Self {
            keys,
            root,
            plaintext_root: plaintext_root.into(),
            vault_id: vault_id.into(),
        })
    }

    /// The vault's master keys.
    #[must_use]
    pub fn keys(&self) -> &MasterKeys {
        &self.keys
    }

    /// The root directory's id.
    #[must_use]
    pub fn root(&self) -> &DirId {
        &self.root
    }

    /// Where the readable files live.
    #[must_use]
    pub fn plaintext_root(&self) -> &Path {
        &self.plaintext_root
    }

    /// The server's id for this vault, used in request paths.
    #[must_use]
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// The id of the directory at plaintext-relative `rel_dir` (`""` for the
    /// root), derived by chaining `child_dir_id` down the encrypted names.
    ///
    /// # Errors
    ///
    /// Propagates crypto errors from name encryption and HMAC.
    pub fn dir_id_for(&self, rel_dir: &str) -> Result<DirId> {
        let mut current = self.root.clone();
        for segment in rel_dir.split('/').filter(|s| !s.is_empty()) {
            let cipher = encrypt_filename(&self.keys.primary, &current, segment)?;
            current = child_dir_id(&self.keys.hmac, &current, &cipher)?;
        }
        Ok(current)
    }

    /// Maps every directory that exists on disk to its id, by walking the
    /// plaintext tree from the root.
    ///
    /// A remote file can only be placed where its directory id appears here; a
    /// directory a peer made that we have never created locally is not
    /// reconstructible from an opaque id, so it is absent from this map and the
    /// engine skips such files rather than misplacing them.
    ///
    /// # Errors
    ///
    /// Propagates filesystem and crypto errors.
    pub fn dir_map(&self) -> Result<HashMap<DirId, String>> {
        let mut map = HashMap::new();
        map.insert(self.root.clone(), String::new());
        // Breadth-first so a parent is always in the map before its children.
        let mut queue: Vec<(DirId, String)> = vec![(self.root.clone(), String::new())];
        while let Some((dir_id, rel)) = queue.pop() {
            let on_disk = if rel.is_empty() {
                self.plaintext_root.clone()
            } else {
                self.plaintext_root.join(&rel)
            };
            let mut names: Vec<String> = Vec::new();
            for entry in std::fs::read_dir(&on_disk)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        names.push(name.to_owned());
                    }
                }
            }
            names.sort();
            for name in names {
                let cipher = encrypt_filename(&self.keys.primary, &dir_id, &name)?;
                let child = child_dir_id(&self.keys.hmac, &dir_id, &cipher)?;
                let child_rel = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                map.insert(child.clone(), child_rel.clone());
                queue.push((child, child_rel));
            }
        }
        Ok(map)
    }

    /// Splits a plaintext-relative path into the directory id, encrypted name,
    /// and plaintext name a file of that path is stored under.
    ///
    /// # Errors
    ///
    /// Propagates crypto errors from name encryption.
    pub fn locate(&self, rel_path: &str) -> Result<(DirId, String, String)> {
        let (rel_dir, name) = match rel_path.rsplit_once('/') {
            Some((dir, name)) => (dir, name),
            None => ("", rel_path),
        };
        let dir_id = self.dir_id_for(rel_dir)?;
        let cipher = encrypt_filename(&self.keys.primary, &dir_id, name)?;
        Ok((dir_id, cipher, name.to_owned()))
    }

    /// The plaintext name a cipher name decrypts to within `dir_id`.
    ///
    /// # Errors
    ///
    /// Propagates crypto errors; a name made for another directory fails
    /// authentication here.
    pub fn plaintext_name(&self, dir_id: &DirId, cipher_name: &str) -> Result<String> {
        Ok(decrypt_filename(&self.keys.primary, dir_id, cipher_name)?)
    }

    /// Chunks and seals `plaintext` as the file identified by `dir_id` /
    /// `cipher_name`.
    ///
    /// # Errors
    ///
    /// Propagates splitter, crypto, and manifest errors.
    pub fn seal(&self, dir_id: &DirId, cipher_name: &str, plaintext: &[u8]) -> Result<Sealed> {
        let mut chunker = FastCdc::new();
        let ranges = chunker.split(plaintext)?;

        let mut chunk_ids = Vec::with_capacity(ranges.len());
        let mut entries = Vec::with_capacity(ranges.len());
        let mut seen: HashSet<ChunkId> = HashSet::new();
        let mut chunks = Vec::new();

        for range in &ranges {
            let data = range.slice(plaintext);
            let (id, stored) = seal_chunk(&self.keys.primary, &self.keys.hmac, data)?;
            entries.push(ChunkEntry {
                id: id.clone(),
                stored_len: stored.len() as u32,
            });
            chunk_ids.push(id.clone());
            if seen.insert(id.clone()) {
                chunks.push((id, stored));
            }
        }

        let manifest = Manifest {
            plaintext_size: plaintext.len() as u64,
            chunks: entries,
        };
        let manifest = encode_manifest(&self.keys.primary, dir_id, cipher_name, &manifest)?;

        Ok(Sealed {
            manifest,
            chunk_ids,
            chunks,
            plaintext_size: plaintext.len() as u64,
        })
    }

    /// Reassembles a file from its manifest, fetching each chunk's stored bytes
    /// through `fetch`, and returns the plaintext plus the chunk ids in file order
    /// (so the caller can record them in the index for reference counting).
    ///
    /// # Errors
    ///
    /// Propagates manifest, chunk, and fetch errors, and reports an integrity
    /// failure if the decrypted chunks do not add up to the manifest's declared
    /// size.
    pub fn open(
        &self,
        dir_id: &DirId,
        cipher_name: &str,
        manifest: &[u8],
        fetch: &mut dyn FnMut(&ChunkId) -> Result<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<ChunkId>)> {
        let manifest = decode_manifest(&self.keys.primary, dir_id, cipher_name, manifest)?;
        let mut out = Vec::with_capacity(usize::try_from(manifest.plaintext_size).unwrap_or(0));
        let mut ids = Vec::with_capacity(manifest.chunks.len());
        for entry in &manifest.chunks {
            let stored = fetch(&entry.id)?;
            let plaintext = open_chunk(&self.keys.primary, &entry.id, &stored)?;
            out.extend_from_slice(&plaintext);
            ids.push(entry.id.clone());
        }
        if out.len() as u64 != manifest.plaintext_size {
            return Err(SyncError::Integrity(
                "chunks did not add up to the manifest size",
            ));
        }
        Ok((out, ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use syncbox_crypto::{ChunkId, MasterKey};

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    fn vault(dir: &Path) -> Vault {
        Vault::new(keys(), "vault", dir).unwrap()
    }

    #[test]
    fn dir_ids_chain_down_a_path_and_are_stable() {
        let dir = std::env::temp_dir();
        let vault = vault(&dir);
        let root = vault.dir_id_for("").unwrap();
        assert_eq!(&root, vault.root());
        let a = vault.dir_id_for("a").unwrap();
        let a_again = vault.dir_id_for("a").unwrap();
        let ab = vault.dir_id_for("a/b").unwrap();
        assert_eq!(a, a_again, "same path, same id");
        assert_ne!(root, a);
        assert_ne!(a, ab);
        // The chain equals an explicit parent-then-child derivation.
        let cipher = syncbox_crypto::names::encrypt_filename(&keys().primary, &root, "a").unwrap();
        assert_eq!(
            a,
            syncbox_crypto::names::child_dir_id(&keys().hmac, &root, &cipher).unwrap()
        );
    }

    #[test]
    fn locate_splits_the_name_and_dir_from_a_path() {
        let dir = std::env::temp_dir();
        let vault = vault(&dir);
        let (dir_id, cipher, name) = vault.locate("docs/notes.txt").unwrap();
        assert_eq!(name, "notes.txt");
        assert_eq!(dir_id, vault.dir_id_for("docs").unwrap());
        // The cipher decrypts back to the bare name within that directory.
        assert_eq!(vault.plaintext_name(&dir_id, &cipher).unwrap(), "notes.txt");
    }

    #[test]
    fn a_sealed_file_round_trips_through_the_manifest() {
        let dir = std::env::temp_dir();
        let vault = vault(&dir);
        let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
        let (dir_id, cipher, _) = vault.locate("fox.txt").unwrap();

        let sealed = vault.seal(&dir_id, &cipher, &plaintext).unwrap();
        assert_eq!(sealed.plaintext_size, plaintext.len() as u64);

        let store: HashMap<ChunkId, Vec<u8>> = sealed.chunks.iter().cloned().collect();
        let mut fetch = |id: &ChunkId| -> Result<Vec<u8>> {
            store
                .get(id)
                .cloned()
                .ok_or(SyncError::Integrity("chunk missing in test store"))
        };
        let (back, ids) = vault
            .open(&dir_id, &cipher, &sealed.manifest, &mut fetch)
            .unwrap();
        assert_eq!(back, plaintext);
        assert_eq!(ids, sealed.chunk_ids, "open reports the chunk ids in order");
    }

    #[test]
    fn identical_bytes_across_files_share_chunk_ids() {
        // The content-derived property at the file level: two files with the same
        // content seal to the same chunk id, so the server stores it once.
        let dir = std::env::temp_dir();
        let vault = vault(&dir);
        let body = vec![7u8; 32];

        let (dir_a, cipher_a, _) = vault.locate("a.txt").unwrap();
        let (dir_b, cipher_b, _) = vault.locate("b.txt").unwrap();
        let sa = vault.seal(&dir_a, &cipher_a, &body).unwrap();
        let sb = vault.seal(&dir_b, &cipher_b, &body).unwrap();

        assert_eq!(sa.chunk_ids, sb.chunk_ids, "same content, same chunk ids");
        assert_eq!(sa.chunks[0].1, sb.chunks[0].1, "and same ciphertext");
    }

    #[test]
    fn an_open_detects_a_short_read() {
        // A manifest that promises more than the chunks provide is an integrity
        // failure, not a silent truncated file.
        let dir = std::env::temp_dir();
        let vault = vault(&dir);
        let plaintext = b"exactly nine bytes!".to_vec();
        let (dir_id, cipher, _) = vault.locate("size.txt").unwrap();
        let sealed = vault.seal(&dir_id, &cipher, &plaintext).unwrap();

        // Fetch returns an empty blob for the one chunk, which decrypts (the tag
        // covers content, not the manifest's size claim) to zero bytes.
        let empty_chunks: HashMap<ChunkId, Vec<u8>> = sealed
            .chunks
            .iter()
            .map(|(id, _)| {
                // A correctly-sealed-but-wrong-size situation: seal empty content
                // under the same id is impossible, so instead fetch nothing and
                // expect the size check or a tag failure to catch it.
                (id.clone(), Vec::new())
            })
            .collect();
        let mut fetch = |id: &ChunkId| -> Result<Vec<u8>> {
            Ok(empty_chunks.get(id).cloned().unwrap_or_default())
        };
        // The empty stored blob is too short to hold a nonce+tag, so open fails as
        // an input error rather than producing a short file.
        assert!(vault
            .open(&dir_id, &cipher, &sealed.manifest, &mut fetch)
            .is_err());
    }
}
