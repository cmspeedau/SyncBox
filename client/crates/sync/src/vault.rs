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

use syncbox_crypto::content::{chunk_id, NONCE_LEN, TAG_LEN};
use syncbox_crypto::names::{child_dir_id, decrypt_filename, encrypt_filename, DirId};
use syncbox_crypto::{
    decode_manifest, encode_manifest, open_chunk, seal_chunk, ChunkEntry, ChunkId, Manifest,
    MasterKeys,
};
use syncbox_transport::dto::SpaceMode;

use crate::chunker::Chunker;
use crate::chunker::FastCdc;
use crate::error::{Result, SyncError};
use crate::plain;

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

/// What a streaming seal learns about a file in one buffered pass: its content
/// addresses and sealed manifest, without ever holding more than one chunk of
/// ciphertext — or any ciphertext at all. Produced by [`Vault::plan_seal`] and
/// consumed by [`Vault::upload_missing`].
#[derive(Debug)]
pub struct SealPlan {
    /// The authenticated manifest bytes, ready to base64 into a revision.
    pub manifest: Vec<u8>,
    /// Chunk ids in file order (with repeats, matching the manifest).
    pub chunk_ids: Vec<ChunkId>,
    /// The distinct ids, in first-appearance order — what to offer the server.
    pub distinct: Vec<ChunkId>,
    /// Plaintext byte count, carried to the revision's `size`.
    pub plaintext_size: u64,
}

/// The working context for one space: how its files are named on the wire, how
/// their bytes become chunks, and where the readable tree sits on disk.
///
/// A space is one of two things. A **vault** holds the master keys and seals
/// every name and chunk; dropping the keys is dropping the data. A **sync
/// space** holds no keys at all — the codec in [`crate::plain`] writes names
/// and bytes as they are — so the server can read, index and serve it, which is
/// the point. Both use the same commit protocol and the same [`crate::Engine`];
/// the mode only chooses the codec.
pub struct Vault {
    mode: SpaceMode,
    keys: Option<MasterKeys>,
    root: DirId,
    plaintext_root: PathBuf,
    vault_id: String,
}

// Keys are secret material; the derived Debug would put them in a log. Debug only
// the non-sensitive coordinates.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("mode", &self.mode)
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
            mode: SpaceMode::Vault,
            keys: Some(keys),
            root,
            plaintext_root: plaintext_root.into(),
            vault_id: vault_id.into(),
        })
    }

    /// A sync space: the server already knows as `vault_id` the space whose
    /// readable files live under `plaintext_root`. No keys are involved — the
    /// codec names and stores the files as they are.
    #[must_use]
    pub fn sync_space(vault_id: impl Into<String>, plaintext_root: impl Into<PathBuf>) -> Self {
        Self {
            mode: SpaceMode::Sync,
            keys: None,
            root: plain::dir_id(""),
            plaintext_root: plaintext_root.into(),
            vault_id: vault_id.into(),
        }
    }

    /// What this space stores.
    #[must_use]
    pub fn mode(&self) -> SpaceMode {
        self.mode
    }

    /// The vault's master keys, or `None` for a sync space.
    #[must_use]
    pub fn keys(&self) -> Option<&MasterKeys> {
        self.keys.as_ref()
    }

    /// The keys a vault-mode codec needs, or an integrity error if this context
    /// is a sync space (which no code path should ask).
    fn vault_keys(&self) -> Result<&MasterKeys> {
        self.keys
            .as_ref()
            .ok_or(SyncError::Integrity("a sync space has no vault keys"))
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
    /// root). A vault chains `child_dir_id` down the encrypted names; a sync
    /// space encodes the path itself.
    ///
    /// # Errors
    ///
    /// Propagates crypto errors from name encryption and HMAC.
    pub fn dir_id_for(&self, rel_dir: &str) -> Result<DirId> {
        if self.mode == SpaceMode::Sync {
            return Ok(plain::dir_id(rel_dir));
        }
        let keys = self.vault_keys()?;
        let mut current = self.root.clone();
        for segment in rel_dir.split('/').filter(|s| !s.is_empty()) {
            let cipher = encrypt_filename(&keys.primary, &current, segment)?;
            current = child_dir_id(&keys.hmac, &current, &cipher)?;
        }
        Ok(current)
    }

    /// The relative path a directory id names, when the mode makes it
    /// recoverable without walking the local tree. A sync space encodes the
    /// path in the id; a vault's ids are HMACs and yield `None`.
    #[must_use]
    pub fn dir_id_to_rel(&self, dir_id: &DirId) -> Option<String> {
        if self.mode == SpaceMode::Sync {
            plain::rel_dir(dir_id)
        } else {
            None
        }
    }

    /// Bytes each stored chunk adds over its plaintext: a nonce and a tag for a
    /// vault, nothing for a sync space.
    #[must_use]
    pub fn stored_overhead(&self) -> u64 {
        if self.mode == SpaceMode::Sync {
            0
        } else {
            (NONCE_LEN + TAG_LEN) as u64
        }
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
                let child_rel = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                let child = if self.mode == SpaceMode::Sync {
                    plain::dir_id(&child_rel)
                } else {
                    let keys = self.vault_keys()?;
                    let cipher = encrypt_filename(&keys.primary, &dir_id, &name)?;
                    child_dir_id(&keys.hmac, &dir_id, &cipher)?
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
        let cipher = if self.mode == SpaceMode::Sync {
            name.to_owned()
        } else {
            encrypt_filename(&self.vault_keys()?.primary, &dir_id, name)?
        };
        Ok((dir_id, cipher, name.to_owned()))
    }

    /// The plaintext name a stored name denotes within `dir_id`.
    ///
    /// A vault decrypts it and fails authentication if it was made for another
    /// directory. A sync space's name is already plaintext, and is refused
    /// unless it is a single safe path component.
    ///
    /// # Errors
    ///
    /// Propagates crypto errors; a name made for another directory fails
    /// authentication here.
    pub fn plaintext_name(&self, dir_id: &DirId, cipher_name: &str) -> Result<String> {
        if self.mode == SpaceMode::Sync {
            if !plain::safe_name(cipher_name) {
                return Err(SyncError::Integrity(
                    "sync-space file name is not one safe path component",
                ));
            }
            return Ok(cipher_name.to_owned());
        }
        Ok(decrypt_filename(
            &self.vault_keys()?.primary,
            dir_id,
            cipher_name,
        )?)
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
        let sync = self.mode == SpaceMode::Sync;
        let keys = if sync { None } else { Some(self.vault_keys()?) };

        let mut chunk_ids = Vec::with_capacity(ranges.len());
        let mut entries = Vec::with_capacity(ranges.len());
        let mut seen: HashSet<ChunkId> = HashSet::new();
        let mut chunks = Vec::new();

        for range in &ranges {
            let data = range.slice(plaintext);
            let (id, stored) = match keys {
                Some(keys) => seal_chunk(&keys.primary, &keys.hmac, data)?,
                // A sync space stores the bytes themselves; the id is their
                // plain hash, so dedup works exactly as it does in a vault.
                None => (plain::chunk_id(data), data.to_vec()),
            };
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
        let manifest = match keys {
            Some(keys) => encode_manifest(&keys.primary, dir_id, cipher_name, &manifest)?,
            None => plain::encode_manifest(&manifest)?,
        };

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
        let manifest = self.decode_manifest(dir_id, cipher_name, manifest)?;
        let mut out = Vec::with_capacity(usize::try_from(manifest.plaintext_size).unwrap_or(0));
        let mut ids = Vec::with_capacity(manifest.chunks.len());
        for entry in &manifest.chunks {
            let stored = fetch(&entry.id)?;
            let plaintext = self.chunk_plaintext(entry, &stored)?;
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

    /// Decodes a stored manifest for this space's mode.
    fn decode_manifest(
        &self,
        dir_id: &DirId,
        cipher_name: &str,
        manifest: &[u8],
    ) -> Result<Manifest> {
        if self.mode == SpaceMode::Sync {
            plain::decode_manifest(manifest)
        } else {
            Ok(decode_manifest(
                &self.vault_keys()?.primary,
                dir_id,
                cipher_name,
                manifest,
            )?)
        }
    }

    /// One stored chunk as plaintext. A vault authenticates it against its id;
    /// a sync space re-hashes it against the id its manifest names, so a
    /// corrupted or swapped blob is refused there too.
    fn chunk_plaintext(&self, entry: &ChunkEntry, stored: &[u8]) -> Result<Vec<u8>> {
        if self.mode == SpaceMode::Sync {
            if stored.len() as u64 != u64::from(entry.stored_len) {
                return Err(SyncError::Integrity(
                    "sync-space chunk has the wrong stored length",
                ));
            }
            if plain::chunk_id(stored) != entry.id {
                return Err(SyncError::Integrity(
                    "sync-space chunk does not match its id",
                ));
            }
            Ok(stored.to_vec())
        } else {
            Ok(open_chunk(&self.vault_keys()?.primary, &entry.id, stored)?)
        }
    }

    /// Streams a file into the plan a push needs: chunk ids and the sealed
    /// manifest, one chunk in memory at a time, and no AES at all — an id is an
    /// HMAC of the content, so the first pass over a file does not pay for the
    /// ciphertext it is only going to skip uploading anyway.
    ///
    /// The plan is only honest while the file holds still; [`Vault::upload_missing`]
    /// re-derives every id from the re-read bytes and refuses a file that moved.
    ///
    /// # Errors
    ///
    /// Propagates reader I/O and chunker, crypto, and manifest errors.
    pub fn plan_seal<R: std::io::Read>(
        &self,
        dir_id: &DirId,
        cipher_name: &str,
        reader: &mut R,
    ) -> Result<SealPlan> {
        let mut chunker = FastCdc::new();
        let sync = self.mode == SpaceMode::Sync;
        let keys = if sync { None } else { Some(self.vault_keys()?) };
        let overhead = self.stored_overhead();
        let mut chunk_ids = Vec::new();
        let mut entries = Vec::new();
        let mut distinct: Vec<ChunkId> = Vec::new();
        let mut seen: HashSet<ChunkId> = HashSet::new();
        let mut size = 0u64;

        chunker.split_stream(reader, |data| {
            let id = match keys {
                Some(keys) => chunk_id(&keys.hmac, data)?,
                None => plain::chunk_id(data),
            };
            size += data.len() as u64;
            entries.push(ChunkEntry {
                stored_len: (data.len() as u64 + overhead) as u32,
                id: id.clone(),
            });
            chunk_ids.push(id.clone());
            if seen.insert(id.clone()) {
                distinct.push(id);
            }
            Ok(())
        })?;

        let manifest = Manifest {
            plaintext_size: size,
            chunks: entries,
        };
        let manifest = match keys {
            Some(keys) => encode_manifest(&keys.primary, dir_id, cipher_name, &manifest)?,
            None => plain::encode_manifest(&manifest)?,
        };
        Ok(SealPlan {
            manifest,
            chunk_ids,
            distinct,
            plaintext_size: size,
        })
    }

    /// The push's second pass: stream the file again, seal each chunk, and hand
    /// the caller the bytes whose ids are `missing` — while proving against
    /// `plan`, chunk by chunk, that the file did not change underneath the first
    /// pass.
    ///
    /// A file edited mid-push is therefore not a corruption risk: either every
    /// re-derived id still matches the plan the commit is about to name, or the
    /// upload aborts and the next pass relists and re-plans the new content.
    /// Bytes uploaded before such an abort are content-addressed orphans the
    /// next pass simply will not re-offer.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::Integrity`] if the file changed, and propagates
    /// reader I/O, crypto, and `upload` errors.
    pub fn upload_missing<R, F>(
        &self,
        reader: &mut R,
        plan: &SealPlan,
        missing: &HashSet<ChunkId>,
        mut upload: F,
    ) -> Result<usize>
    where
        R: std::io::Read,
        F: FnMut(&ChunkId, &[u8]) -> Result<()>,
    {
        let mut chunker = FastCdc::new();
        let sync = self.mode == SpaceMode::Sync;
        let keys = if sync { None } else { Some(self.vault_keys()?) };
        let mut index = 0usize;
        let mut sent: HashSet<ChunkId> = HashSet::new();
        let mut uploads = 0usize;

        chunker.split_stream(reader, |data| {
            let (id, stored) = match keys {
                Some(keys) => seal_chunk(&keys.primary, &keys.hmac, data)?,
                None => (plain::chunk_id(data), data.to_vec()),
            };
            match plan.chunk_ids.get(index) {
                Some(expected) if *expected == id => {}
                _ => {
                    return Err(SyncError::Integrity(
                        "the file changed while it was being pushed; this pass is abandoned",
                    ))
                }
            }
            index += 1;
            if missing.contains(&id) && sent.insert(id.clone()) {
                upload(&id, &stored)?;
                uploads += 1;
            }
            Ok(())
        })?;

        if index != plan.chunk_ids.len() {
            return Err(SyncError::Integrity(
                "the file changed while it was being pushed; this pass is abandoned",
            ));
        }
        Ok(uploads)
    }

    /// [`Vault::open`] with the plaintext handed out chunk by chunk instead of
    /// assembled: a 4 GiB file reassembles through a 64 KiB window.
    ///
    /// # Errors
    ///
    /// Propagates manifest, chunk, fetch, and `write` errors, and reports an
    /// integrity failure if the decrypted chunks do not add up to the manifest's
    /// declared size — a lying manifest can fill the `write` sink, so callers
    /// should stream to a temporary the rename will not promote until this
    /// returns.
    pub fn open_stream(
        &self,
        dir_id: &DirId,
        cipher_name: &str,
        manifest: &[u8],
        fetch: &mut dyn FnMut(&ChunkId) -> Result<Vec<u8>>,
        write: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Vec<ChunkId>> {
        let manifest = self.decode_manifest(dir_id, cipher_name, manifest)?;
        let mut ids = Vec::with_capacity(manifest.chunks.len());
        let mut total = 0u64;
        for entry in &manifest.chunks {
            let stored = fetch(&entry.id)?;
            let plaintext = self.chunk_plaintext(entry, &stored)?;
            total += plaintext.len() as u64;
            write(&plaintext)?;
            ids.push(entry.id.clone());
        }
        if total != manifest.plaintext_size {
            return Err(SyncError::Integrity(
                "chunks did not add up to the manifest size",
            ));
        }
        Ok(ids)
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
    fn a_sync_space_names_directories_and_files_in_the_clear() {
        let dir = std::env::temp_dir();
        let space = Vault::sync_space("space", &dir);
        assert_eq!(space.mode(), SpaceMode::Sync);
        assert!(space.keys().is_none(), "a sync space holds no keys");
        assert_eq!(space.stored_overhead(), 0, "nothing is added to a chunk");
        assert_eq!(
            vault(&dir).stored_overhead(),
            (NONCE_LEN + TAG_LEN) as u64,
            "a vault's chunk carries a nonce and a tag"
        );

        // The directory id decodes back to the path, and the stored name is the
        // plaintext name — the two facts the server's browse surface (S3) reads.
        let root = space.dir_id_for("").unwrap();
        assert_eq!(space.dir_id_to_rel(&root).as_deref(), Some(""));
        let (dir_id, cipher, name) = space.locate("docs/notes.txt").unwrap();
        assert_eq!(name, "notes.txt");
        assert_eq!(cipher, "notes.txt", "the stored name is the plaintext name");
        assert_eq!(space.dir_id_to_rel(&dir_id).as_deref(), Some("docs"));
        assert_eq!(space.plaintext_name(&dir_id, &cipher).unwrap(), "notes.txt");

        // A vault's ids are HMACs, so they carry no path back.
        let v = vault(&dir);
        assert_eq!(v.dir_id_to_rel(&v.dir_id_for("docs").unwrap()), None);
    }

    #[test]
    fn a_sync_file_round_trips_and_the_bytes_are_the_plaintext() {
        let space = Vault::sync_space("space", std::env::temp_dir());
        let plaintext = noisy(150_000);
        let (dir_id, cipher, _) = space.locate("big.bin").unwrap();
        let sealed = space.seal(&dir_id, &cipher, &plaintext).unwrap();
        assert_eq!(sealed.plaintext_size, plaintext.len() as u64);

        // Every stored chunk hashes to the id it is filed under, and the ids in
        // order spell the file exactly — the server holds the file's own bytes.
        let store: HashMap<ChunkId, Vec<u8>> = sealed.chunks.iter().cloned().collect();
        for (id, stored) in &store {
            assert_eq!(&plain::chunk_id(stored), id, "a chunk matches its id");
        }
        let joined: Vec<u8> = sealed
            .chunk_ids
            .iter()
            .flat_map(|id| store[id].clone())
            .collect();
        assert_eq!(joined, plaintext);

        let mut fetch = |id: &ChunkId| -> Result<Vec<u8>> {
            store
                .get(id)
                .cloned()
                .ok_or(SyncError::Integrity("chunk missing in test store"))
        };
        let (back, ids) = space
            .open(&dir_id, &cipher, &sealed.manifest, &mut fetch)
            .unwrap();
        assert_eq!(back, plaintext);
        assert_eq!(ids, sealed.chunk_ids);
    }

    #[test]
    fn a_sync_open_refuses_a_chunk_that_does_not_match_its_id() {
        // No AEAD tag stands behind a sync chunk, so the reader re-hashes it. A
        // swapped or corrupted blob must not be written to the file.
        let space = Vault::sync_space("space", std::env::temp_dir());
        let (dir_id, cipher, _) = space.locate("f.txt").unwrap();
        let sealed = space.seal(&dir_id, &cipher, b"real bytes").unwrap();
        let mut fetch = |_id: &ChunkId| -> Result<Vec<u8>> { Ok(b"other bytes".to_vec()) };
        assert!(space
            .open(&dir_id, &cipher, &sealed.manifest, &mut fetch)
            .is_err());
    }

    #[test]
    fn a_sync_space_refuses_a_name_that_would_escape_the_folder() {
        // A sync space has no tag to verify a hostile or broken server's name
        // against, so it refuses anything but one safe path component.
        let space = Vault::sync_space("space", std::env::temp_dir());
        let root = space.dir_id_for("").unwrap();
        assert!(space.plaintext_name(&root, "../escape").is_err());
        assert!(space.plaintext_name(&root, "a/b").is_err());
        assert!(space.plaintext_name(&root, "").is_err());
        assert!(space.plaintext_name(&root, "notes.txt").is_ok());
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

    /// Deterministic pseudo-random bytes, so the streaming tests span several
    /// chunk boundaries reproducibly.
    fn noisy(len: usize) -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn plan_and_upload_reproduce_a_buffered_seal_exactly() {
        let dir = std::env::temp_dir();
        let vault = vault(&dir);
        let data = noisy(250_000);
        let (dir_id, cipher, _name) = vault.locate("deep/streaming.bin").unwrap();

        let buffered = vault.seal(&dir_id, &cipher, &data).unwrap();
        let plan = vault
            .plan_seal(&dir_id, &cipher, &mut data.as_slice())
            .unwrap();
        assert_eq!(plan.manifest, buffered.manifest, "same manifest bytes");
        assert_eq!(plan.chunk_ids, buffered.chunk_ids);
        assert_eq!(plan.plaintext_size, data.len() as u64);
        assert_eq!(
            plan.distinct,
            buffered
                .chunks
                .iter()
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        );

        // Uploading everything the plan says is new must yield the buffered
        // seal's chunks — same ids, same bytes, same deduplicated order.
        let missing: HashSet<ChunkId> = plan.distinct.iter().cloned().collect();
        let mut got = Vec::new();
        let uploads = vault
            .upload_missing(&mut data.as_slice(), &plan, &missing, |id, stored| {
                got.push((id.clone(), stored.to_vec()));
                Ok(())
            })
            .unwrap();
        assert_eq!(uploads, got.len());
        assert_eq!(got, buffered.chunks);
    }

    #[test]
    fn a_file_edited_mid_upload_aborts_the_pass() {
        let dir = std::env::temp_dir();
        let vault = vault(&dir);
        let data = noisy(200_000);
        let (dir_id, cipher, _name) = vault.locate("moving.bin").unwrap();
        let plan = vault
            .plan_seal(&dir_id, &cipher, &mut data.as_slice())
            .unwrap();

        let mut mutated = data.clone();
        mutated[1234] ^= 0xFF; // inside the first chunk: the re-derived id cannot match
        let missing: HashSet<ChunkId> = plan.distinct.iter().cloned().collect();
        let error = vault
            .upload_missing(&mut mutated.as_slice(), &plan, &missing, |_, _| Ok(()))
            .expect_err("a moved file must not be pushed against the old plan");
        assert!(
            matches!(error, SyncError::Integrity(_)),
            "got {error:?}, want an integrity abort"
        );
    }

    #[test]
    fn open_stream_hands_back_what_open_would_return() {
        let dir = std::env::temp_dir();
        let vault = vault(&dir);
        let data = noisy(250_000);
        let (dir_id, cipher, _name) = vault.locate("reassemble.bin").unwrap();
        let sealed = vault.seal(&dir_id, &cipher, &data).unwrap();

        let chunks: HashMap<ChunkId, Vec<u8>> = sealed.chunks.iter().cloned().collect();
        let mut out = Vec::new();
        let ids = vault
            .open_stream(
                &dir_id,
                &cipher,
                &sealed.manifest,
                &mut |id| {
                    chunks
                        .get(id)
                        .cloned()
                        .ok_or(SyncError::Integrity("test fetch out of range"))
                },
                &mut |bytes| {
                    out.extend_from_slice(bytes);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(ids, sealed.chunk_ids);
        assert_eq!(out, data);
    }

    #[test]
    fn open_stream_refuses_a_manifest_that_lies_about_size() {
        let dir = std::env::temp_dir();
        let vault = vault(&dir);
        let data = noisy(150_000);
        let (dir_id, cipher, _name) = vault.locate("liar.bin").unwrap();
        let sealed = vault.seal(&dir_id, &cipher, &data).unwrap();

        // A manifest edited to promise one byte more than its chunks can deliver —
        // still a valid blob the keys will open, caught only by the sum.
        let mut lying = decode_manifest(
            &vault.vault_keys().unwrap().primary,
            &dir_id,
            &cipher,
            &sealed.manifest,
        )
        .unwrap();
        lying.plaintext_size += 1;
        let lying = encode_manifest(
            &vault.vault_keys().unwrap().primary,
            &dir_id,
            &cipher,
            &lying,
        )
        .unwrap();

        let chunks: HashMap<ChunkId, Vec<u8>> = sealed.chunks.iter().cloned().collect();
        let error = vault
            .open_stream(
                &dir_id,
                &cipher,
                &lying,
                &mut |id| {
                    chunks
                        .get(id)
                        .cloned()
                        .ok_or(SyncError::Integrity("test fetch out of range"))
                },
                &mut |_| Ok(()),
            )
            .expect_err("a short delivery is an integrity failure");
        assert!(matches!(error, SyncError::Integrity(_)));
    }
}
