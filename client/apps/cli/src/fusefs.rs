//! A read-only FUSE view of a vault — the `fuser` adapter.
//!
//! It maps the kernel's FUSE callbacks onto the kernel-free [`Fs`] the `syncbox-mount`
//! crate already provides, plus a [`Vault`] and a [`ContentStore`] for content. All the
//! interesting logic (what the tree *is*, and turning a path back into plaintext) lives
//! in `syncbox-mount`; this is the thin translation layer from `Fs` answers to FUSE
//! replies. It is deliberately the only `fuser`-dependent code, behind the CLI's
//! `mount` feature, so the workspace gate and `cargo test --workspace` compile no FUSE
//! binding.
//!
//! Read-only: the mount is presented with `MountOption::RO`, so the kernel refuses
//! writes before they reach us; we implement only the read operations and let the rest
//! default. `open` decrypts a whole file once into the handle's cache, so a `read`
//! answers from RAM (chunk-range reads are a later optimisation).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::time::Duration;

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, Request, FUSE_ROOT_ID,
};
use syncbox_mount::{ContentStore, Fs, NodeKind};
use syncbox_sync::Vault;

/// How long the kernel may cache an entry/attribute before re-asking. Short, since the
/// view is rebuilt per mount and content is static for its lifetime.
const TTL: Duration = Duration::from_secs(1);

/// A read-only filesystem over a vault snapshot, its keys, and its content store.
pub struct ReadonlyFS<S: ContentStore> {
    fs: Fs,
    vault: Vault,
    store: S,
    /// Inode number → path (`""` is the root). Root is always [`FUSE_ROOT_ID`].
    by_ino: HashMap<u64, String>,
    by_path: HashMap<String, u64>,
    next_ino: u64,
    /// Open-file cache: handle → the file's whole decrypted bytes.
    open: HashMap<u64, Vec<u8>>,
    next_fh: u64,
}

impl<S: ContentStore> ReadonlyFS<S> {
    /// Builds the adapter over an already-assembled [`Fs`] snapshot.
    #[must_use]
    pub fn new(fs: Fs, vault: Vault, store: S) -> Self {
        let mut by_ino = HashMap::new();
        let mut by_path = HashMap::new();
        by_ino.insert(FUSE_ROOT_ID, String::new());
        by_path.insert(String::new(), FUSE_ROOT_ID);
        Self {
            fs,
            vault,
            store,
            by_ino,
            by_path,
            next_ino: FUSE_ROOT_ID + 1,
            open: HashMap::new(),
            next_fh: 1,
        }
    }

    /// The inode for `path`, minting one the first time it is seen.
    fn ensure_ino(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.by_path.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.by_ino.insert(ino, path.to_owned());
        self.by_path.insert(path.to_owned(), ino);
        ino
    }

    /// The path an inode names, if it was handed out.
    fn path_of(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(String::as_str)
    }

    /// Attributes for `path`, minting its inode. `None` if nothing is there.
    fn attr(&mut self, path: &str) -> Option<FileAttr> {
        let node = self.fs.lookup(path)?;
        let ino = self.ensure_ino(path);
        let dir = node.is_dir();
        Some(FileAttr {
            ino,
            size: node.size,
            blocks: node.size.div_ceil(512),
            atime: std::time::UNIX_EPOCH,
            mtime: std::time::UNIX_EPOCH,
            ctime: std::time::UNIX_EPOCH,
            crtime: std::time::UNIX_EPOCH,
            kind: if dir {
                FileType::Directory
            } else {
                FileType::RegularFile
            },
            perm: if dir { 0o555 } else { 0o444 },
            nlink: if dir { 2 } else { 1 },
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }

    /// Joins a directory path and a child name into a child path.
    fn child_path(parent: &str, name: &str) -> String {
        if parent.is_empty() {
            name.to_owned()
        } else {
            format!("{parent}/{name}")
        }
    }
}

impl<S: ContentStore> Filesystem for ReadonlyFS<S> {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_path = self.path_of(parent).unwrap_or("").to_owned();
        let child = Self::child_path(&parent_path, &name.to_string_lossy());
        match self.attr(&child) {
            Some(attr) => reply.entry(&TTL, &attr, 0),
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(path) = self.path_of(ino).map(str::to_owned) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.attr(&path) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(libc::ENOENT),
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.path_of(ino).map(str::to_owned) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(children) = self.fs.readdir(&path) else {
            reply.error(libc::ENOTDIR);
            return;
        };

        // "." then ".." then the real children, as a flat stream the kernel resumes by
        // offset. `ensure_ino` gives every child a stable inode before it is listed.
        let self_ino = self.ensure_ino(&path);
        let parent_path = path.rsplit_once('/').map_or("", |(p, _)| p).to_owned();
        let parent_ino = self.ensure_ino(&parent_path);

        let mut items: Vec<(u64, FileType, String)> = Vec::with_capacity(children.len() + 2);
        items.push((self_ino, FileType::Directory, ".".to_owned()));
        items.push((parent_ino, FileType::Directory, "..".to_owned()));
        for child in &children {
            let cpath = Self::child_path(&path, &child.name);
            let ino = self.ensure_ino(&cpath);
            let kind = if child.kind == NodeKind::Directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            items.push((ino, kind, child.name.clone()));
        }

        for (index, (child_ino, kind, name)) in
            items.into_iter().enumerate().skip(offset.max(0) as usize)
        {
            if reply.add(child_ino, (index + 1) as i64, kind, name) {
                return; // buffer full; the kernel re-asks from this offset
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let Some(path) = self.path_of(ino).map(str::to_owned) else {
            reply.error(libc::ENOENT);
            return;
        };
        if self.fs.is_dir(&path) {
            reply.error(libc::EISDIR);
            return;
        }
        // Decrypt once; the read handle serves slices from this cache.
        let bytes = match self.fs.read_all(&self.vault, &self.store, &path) {
            Ok(bytes) => bytes,
            Err(_) => {
                reply.error(libc::EIO);
                return;
            }
        };
        let fh = self.next_fh;
        self.next_fh += 1;
        self.open.insert(fh, bytes);
        reply.opened(fh, 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(bytes) = self.open.get(&fh) else {
            reply.error(libc::ENOENT);
            return;
        };
        let start = offset.max(0) as usize;
        if start >= bytes.len() {
            reply.data(&[]);
            return;
        }
        let end = start.saturating_add(size as usize).min(bytes.len());
        reply.data(&bytes[start..end]);
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.open.remove(&fh);
        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration as StdDuration, Instant};

    use fuser::{spawn_mount2, MountOption};
    use syncbox_crypto::{MasterKey, MasterKeys};
    use syncbox_index::MemoryIndex;
    use syncbox_mount::{Fs, FsMut, MemoryStore};
    use syncbox_sync::Vault;

    use super::ReadonlyFS;

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    /// Mounts a vault staged with two files and reads it back through a real FUSE
    /// mount. Ignored by default (needs a FUSE driver); run with
    /// `cargo test -p syncbox-cli --features mount -- --ignored`.
    #[test]
    #[ignore = "requires a FUSE driver (/dev/fuse, fusermount3)"]
    fn a_real_readonly_mount_serves_the_staged_files() {
        let mountpoint = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let vault = Vault::new(keys(), "vault", files.path()).expect("vault");

        // Stage content through the write model: seals into an in-memory store and
        // records it in the index, exactly as a local write would.
        let mut index = MemoryIndex::default();
        let mut store = MemoryStore::new();
        let hello = b"read through a real FUSE mount".to_vec();
        let readme = b"# docs\n\nhello from the vault\n".to_vec();
        {
            let mut fs = FsMut::new(&mut index, &vault, &mut store);
            fs.write("hello.txt", &hello).expect("write hello");
            fs.write("docs/readme.md", &readme).expect("write readme");
        }

        let view = ReadonlyFS::new(Fs::from_index(&index), vault, store);
        let session = spawn_mount2(
            view,
            mountpoint.path(),
            &[MountOption::RO, MountOption::FSName("syncbox".to_owned())],
        )
        .expect("mount");

        // Wait for the mount to come up, then read it back with plain std::fs.
        let root = mountpoint.path();
        wait_until(
            || root.join("hello.txt").exists(),
            StdDuration::from_secs(5),
        )
        .expect("mount became ready");
        assert_eq!(std::fs::read(root.join("hello.txt")).unwrap(), hello);
        assert_eq!(std::fs::read(root.join("docs/readme.md")).unwrap(), readme);

        let mut names: Vec<String> = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["docs".to_owned(), "hello.txt".to_owned()]);

        // Unmount and wait, so the temp dir can be cleaned up.
        session.join();
    }

    fn wait_until<F: Fn() -> bool>(pred: F, timeout: StdDuration) -> Option<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if pred() {
                return Some(());
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(StdDuration::from_millis(50));
        }
    }
}
