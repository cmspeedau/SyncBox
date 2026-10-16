//! The `fuser` adapters: read-only and writable FUSE views of a vault.
//!
//! All the interesting logic (what the tree *is*, and turning a path back into
//! plaintext) lives in `syncbox-mount`; this is the thin translation layer from `Fs`
//! answers to FUSE replies, and the only `fuser`-dependent code in the workspace.
//! It sits behind the CLI's `mount` feature, so the workspace gate and `cargo test
//! --workspace` compile no FUSE binding.
//!
//! [`ReadonlyFS`] (the default mount) implements the read operations only, and the
//! mount itself is presented `RO` so the kernel refuses writes before they arrive.
//!
//! [`WritableFS`] adds `create`/`write`/`setattr`-truncate/`unlink`/`rename`/`mkdir`/
//! `rmdir` routed through [`FsMut`]: a write seals through the vault, lands its chunks
//! and manifest in the [`WriteStore`], and records a **dirty** index entry — the same
//! outcome a local write has everywhere else, ready for a sync to push. Writes are
//! buffered per handle and committed on close; directories created with `mkdir` live
//! in memory until a file lands under them, because the index namespace stores only
//! files. A `--writable` mount is therefore a *local* edit surface until the
//! store-backed push mode lands: nothing on disk is plaintext.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, FUSE_ROOT_ID,
};
use syncbox_index::Index;
use syncbox_mount::{ContentStore, DirEntry, Fs, FsMut, NodeKind, WriteStore};
use syncbox_sync::Vault;

/// How long the kernel may cache an entry/attribute before re-asking. Short, since a
/// write invalidates the snapshot and staleness should expire fast.
const TTL: Duration = Duration::from_secs(1);

/// The writable mount answers with a zero TTL everywhere: a close can change a file's
/// size with no other signal, so the kernel must revalidate — never clamp a read to a
/// stale cached size.
const WRITE_TTL: Duration = Duration::ZERO;

// The Linux `open(2)` access bits the kernel hands through `open`'s flags unchanged.
const O_ACCMODE: i32 = 3;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const O_TRUNC: i32 = 0o1000;

/// Join a directory path and a child name into a child path (`""` is the root).
fn child_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

/// A `FileAttr` for a node, with the ownership the request came from so the
/// single-uid mount can write its own files under `DefaultPermissions`.
fn attr_of(ino: u64, dir: bool, size: u64, uid: u32, gid: u32, writable: bool) -> FileAttr {
    let perm = match (writable, dir) {
        (true, true) => 0o755,
        (true, false) => 0o644,
        (false, true) => 0o555,
        (false, false) => 0o444,
    };
    FileAttr {
        ino,
        size,
        blocks: size.div_ceil(512),
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: if dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        },
        perm,
        nlink: if dir { 2 } else { 1 },
        uid,
        gid,
        rdev: 0,
        blksize: 4096,
        flags: 0,
    }
}

/// Inode numbers ↔ paths. Root is always [`FUSE_ROOT_ID`]; every other inode is
/// minted the first time its path is named, and dropped when the path is removed so a
/// re-created file never reuses the old handle's inode.
#[derive(Debug)]
struct Inodes {
    by_ino: HashMap<u64, String>,
    by_path: HashMap<String, u64>,
    next_ino: u64,
}

impl Inodes {
    fn new() -> Self {
        let mut table = Self {
            by_ino: HashMap::new(),
            by_path: HashMap::new(),
            next_ino: FUSE_ROOT_ID + 1,
        };
        table.by_ino.insert(FUSE_ROOT_ID, String::new());
        table.by_path.insert(String::new(), FUSE_ROOT_ID);
        table
    }

    fn ensure(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.by_path.get(path) {
            return ino;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.by_ino.insert(ino, path.to_owned());
        self.by_path.insert(path.to_owned(), ino);
        ino
    }

    fn path_of(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(String::as_str)
    }

    fn forget(&mut self, path: &str) {
        if let Some(ino) = self.by_path.remove(path) {
            self.by_ino.remove(&ino);
        }
    }
}

/// Apply a write at `offset` to a whole-file buffer, zero-filling any gap it skips.
fn patch(buf: &mut Vec<u8>, offset: usize, data: &[u8]) {
    let end = offset + data.len();
    if buf.len() < end {
        buf.resize(end, 0);
    }
    buf[offset..end].copy_from_slice(data);
}

/// A directory listing that merges the index-derived tree with in-memory empty
/// directories, deduplicated by name and sorted. `None` if `dir` is no directory in
/// either source — including a directory that exists *only* as an `mkdir`'d prefix.
fn list_dir(fs: &Fs, empty: &BTreeSet<String>, dir: &str) -> Option<Vec<DirEntry>> {
    let mut children = fs.readdir(dir).unwrap_or_default();
    let mut found = fs.lookup(dir).is_some_and(|n| n.is_dir());
    let mut names: HashSet<String> = children.iter().map(|c| c.name.clone()).collect();
    for candidate in empty {
        let rest = if dir.is_empty() {
            candidate.as_str()
        } else {
            match candidate.strip_prefix(dir) {
                Some(r) => r.strip_prefix('/').unwrap_or(""),
                None => "",
            }
        };
        if rest.is_empty() {
            continue;
        }
        // Some empty directory lives under `dir`, so `dir` is a directory too.
        found = true;
        let name = rest.split('/').next().unwrap_or("");
        if names.insert(name.to_owned()) {
            children.push(DirEntry {
                name: name.to_owned(),
                kind: NodeKind::Directory,
                size: 0,
            });
        }
    }
    if !found {
        return None;
    }
    children.sort_by(|a, b| a.name.cmp(&b.name));
    Some(children)
}

/// A read-only filesystem over a vault snapshot, its keys, and its content store.
pub struct ReadonlyFS<S: ContentStore> {
    fs: Fs,
    vault: Vault,
    store: S,
    inodes: Inodes,
    /// Open-file cache: handle → the file's whole decrypted bytes.
    open: HashMap<u64, Vec<u8>>,
    next_fh: u64,
}

impl<S: ContentStore> ReadonlyFS<S> {
    /// Builds the adapter over an already-assembled [`Fs`] snapshot.
    #[must_use]
    pub fn new(fs: Fs, vault: Vault, store: S) -> Self {
        Self {
            fs,
            vault,
            store,
            inodes: Inodes::new(),
            open: HashMap::new(),
            next_fh: 1,
        }
    }

    /// Attributes for `path`, minting its inode. `None` if nothing is there.
    fn attr(&mut self, path: &str) -> Option<FileAttr> {
        let node = self.fs.lookup(path)?;
        let ino = self.inodes.ensure(path);
        Some(attr_of(ino, node.is_dir(), node.size, 0, 0, false))
    }
}

impl<S: ContentStore> Filesystem for ReadonlyFS<S> {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_path = self.inodes.path_of(parent).unwrap_or("").to_owned();
        let child = child_path(&parent_path, &name.to_string_lossy());
        match self.attr(&child) {
            Some(attr) => reply.entry(&TTL, &attr, 0),
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(path) = self.inodes.path_of(ino).map(str::to_owned) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.attr(&path) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.inodes.path_of(ino).map(str::to_owned) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(children) = self.fs.readdir(&path) else {
            reply.error(libc::ENOTDIR);
            return;
        };
        let parent = path.rsplit_once('/').map_or("", |(p, _)| p).to_owned();
        let parent_ino = self.inodes.ensure(&parent);
        let mut items: Vec<(u64, FileType, String)> = Vec::with_capacity(children.len() + 2);
        items.push((ino, FileType::Directory, ".".to_owned()));
        items.push((parent_ino, FileType::Directory, "..".to_owned()));
        for child in &children {
            let cpath = child_path(&path, &child.name);
            let child_ino = self.inodes.ensure(&cpath);
            let kind = if child.kind == NodeKind::Directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            items.push((child_ino, kind, child.name.clone()));
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

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let Some(path) = self.inodes.path_of(ino).map(str::to_owned) else {
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

/// A writable filesystem over a live index, a [`Vault`], and a [`WriteStore`].
///
/// Reads serve from an `Fs` snapshot rebuilt after every mutation. Writes to an open
/// handle buffer the whole file in RAM and seal it once, on close — matching the
/// whole-file read model and keeping the commit atomic.
pub struct WritableFS<I: Index, S: WriteStore> {
    index: I,
    vault: Vault,
    store: S,
    fs: Fs,
    /// `mkdir`ed directories with no file under them yet — memory-only, per the
    /// index-namespace rule that a stored directory is a file's prefix.
    empty_dirs: BTreeSet<String>,
    inodes: Inodes,
    /// Read handles: handle → the file's whole decrypted bytes.
    reads: HashMap<u64, Vec<u8>>,
    /// Write handles: handle → (path, buffered whole file), sealed on release.
    writes: HashMap<u64, (String, Vec<u8>)>,
    next_fh: u64,
}

impl<I: Index, S: WriteStore> WritableFS<I, S> {
    /// Takes ownership of the live pieces and snapshots the tree from the index.
    #[must_use]
    pub fn new(index: I, vault: Vault, store: S) -> Self {
        let fs = Fs::from_index(&index);
        Self {
            index,
            vault,
            store,
            fs,
            empty_dirs: BTreeSet::new(),
            inodes: Inodes::new(),
            reads: HashMap::new(),
            writes: HashMap::new(),
            next_fh: 1,
        }
    }

    /// Re-snapshot the tree from the index after a mutation.
    fn refresh(&mut self) {
        self.fs = Fs::from_index(&self.index);
    }

    /// `(is_dir, size)` for `path`, counting in-memory empty directories.
    fn node(&self, path: &str) -> Option<(bool, u64)> {
        if let Some(n) = self.fs.lookup(path) {
            return Some((n.is_dir(), n.size));
        }
        if !path.is_empty() && self.empty_dirs.contains(path) {
            return Some((true, 0));
        }
        None
    }

    fn attr(&mut self, path: &str, req: &Request<'_>) -> Option<FileAttr> {
        let (dir, size) = self.node(path)?;
        let ino = self.inodes.ensure(path);
        Some(attr_of(ino, dir, size, req.uid(), req.gid(), true))
    }

    /// The absolute path of a child under the directory named by `parent`'s inode.
    fn child_of(&self, parent: u64, name: &OsStr) -> String {
        let parent_path = self.inodes.path_of(parent).unwrap_or("").to_owned();
        child_path(&parent_path, &name.to_string_lossy())
    }

    /// The directory part of a path (`""` for a top-level name).
    fn parent_of(path: &str) -> &str {
        match path.rfind('/') {
            Some(index) => &path[..index],
            None => "",
        }
    }
}

impl<I: Index, S: WriteStore> Filesystem for WritableFS<I, S> {
    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let child = self.child_of(parent, name);
        match self.attr(&child, req) {
            Some(attr) => reply.entry(&WRITE_TTL, &attr, 0),
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let Some(path) = self.inodes.path_of(ino).map(str::to_owned) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.attr(&path, req) {
            Some(attr) => reply.attr(&WRITE_TTL, &attr),
            None => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.inodes.path_of(ino).map(str::to_owned) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(children) = list_dir(&self.fs, &self.empty_dirs, &path) else {
            reply.error(libc::ENOTDIR);
            return;
        };
        let parent_ino = {
            let parent = Self::parent_of(&path).to_owned();
            self.inodes.ensure(&parent)
        };
        let mut items: Vec<(u64, FileType, String)> = Vec::with_capacity(children.len() + 2);
        items.push((ino, FileType::Directory, ".".to_owned()));
        items.push((parent_ino, FileType::Directory, "..".to_owned()));
        for child in &children {
            let cpath = child_path(&path, &child.name);
            let child_ino = self.inodes.ensure(&cpath);
            let kind = if child.kind == NodeKind::Directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            items.push((child_ino, kind, child.name.clone()));
        }
        for (index, (child_ino, kind, name)) in
            items.into_iter().enumerate().skip(offset.max(0) as usize)
        {
            if reply.add(child_ino, (index + 1) as i64, kind, name) {
                return;
            }
        }
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request<'_>, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    /// `open(O_CREAT)` lands here: create the record empty, then the kernel writes
    /// through the handle we hand back and the seal happens on close.
    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let path = self.child_of(parent, name);
        if self.node(&path).is_some() {
            reply.error(libc::EEXIST);
            return;
        }
        let created = FsMut::new(&mut self.index, &self.vault, &mut self.store).create(&path);
        self.refresh();
        if created.is_err() {
            reply.error(libc::EIO);
            return;
        }
        let fh = self.next_fh;
        self.next_fh += 1;
        self.writes.insert(fh, (path.clone(), Vec::new()));
        match self.attr(&path, req) {
            Some(attr) => reply.created(&WRITE_TTL, &attr, 0, fh, 0),
            None => reply.error(libc::EIO),
        }
    }

    /// `O_TRUNC` on open just yields an empty buffer; the seal happens on close.
    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        let Some(path) = self.inodes.path_of(ino).map(str::to_owned) else {
            reply.error(libc::ENOENT);
            return;
        };
        if matches!(self.node(&path), Some((true, _))) {
            reply.error(libc::EISDIR);
            return;
        }
        let fh = self.next_fh;
        self.next_fh += 1;
        if matches!(flags & O_ACCMODE, O_WRONLY | O_RDWR) {
            // Start from the current plaintext so a partial write leaves the rest of
            // the file intact; an O_TRUNC open starts from nothing.
            let buf = if flags & O_TRUNC != 0 {
                Vec::new()
            } else {
                match self.fs.read_all(&self.vault, &self.store, &path) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            };
            self.writes.insert(fh, (path, buf));
        } else {
            let bytes = match self.fs.read_all(&self.vault, &self.store, &path) {
                Ok(bytes) => bytes,
                Err(_) => {
                    reply.error(libc::EIO);
                    return;
                }
            };
            self.reads.insert(fh, bytes);
        }
        reply.opened(fh, 0);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let Ok(start) = usize::try_from(offset) else {
            reply.error(libc::EINVAL);
            return;
        };
        let Some((_, buf)) = self.writes.get_mut(&fh) else {
            reply.error(libc::EBADF);
            return;
        };
        patch(buf, start, data);
        reply.written(data.len() as u32);
    }

    /// Reads serve from the read cache, or — for a read/write handle — from the live
    /// write buffer, so a handle sees its own bytes.
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
        let bytes = match self.reads.get(&fh) {
            Some(buf) => buf.as_slice(),
            None => match self.writes.get(&fh) {
                Some((_, buf)) => buf.as_slice(),
                None => {
                    reply.error(libc::ENOENT);
                    return;
                }
            },
        };
        let start = offset.max(0) as usize;
        if start >= bytes.len() {
            reply.data(&[]);
            return;
        }
        let end = start.saturating_add(size as usize).min(bytes.len());
        reply.data(&bytes[start..end]);
    }

    /// Closing a write handle is the commit: seal, store, dirty the index record.
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
        self.reads.remove(&fh);
        if let Some((path, buf)) = self.writes.remove(&fh) {
            let sealed =
                FsMut::new(&mut self.index, &self.vault, &mut self.store).write(&path, &buf);
            self.refresh();
            if sealed.is_err() {
                reply.error(libc::EIO);
                return;
            }
        }
        reply.ok();
    }

    /// Only `size` is honoured (a truncate); mode/ownership/time updates are accepted
    /// and acknowledged unchanged — the vault tracks none of them.
    fn setattr(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<std::time::SystemTime>,
        fh: Option<u64>,
        _crtime: Option<std::time::SystemTime>,
        _chgtime: Option<std::time::SystemTime>,
        _bkuptime: Option<std::time::SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.inodes.path_of(ino).map(str::to_owned) else {
            reply.error(libc::ENOENT);
            return;
        };
        if let Some(len) = size {
            let buffered = fh.and_then(|f| self.writes.get_mut(&f));
            if let Some((_, buf)) = buffered {
                // A handle holds buffered bytes: resize the buffer; it seals on close.
                match usize::try_from(len) {
                    Ok(want) => {
                        buf.truncate(want);
                        buf.resize(want, 0);
                    }
                    Err(_) => {
                        reply.error(libc::EINVAL);
                        return;
                    }
                }
            } else {
                let truncated =
                    FsMut::new(&mut self.index, &self.vault, &mut self.store).truncate(&path, len);
                self.refresh();
                if truncated.is_err() {
                    reply.error(libc::EIO);
                    return;
                }
            }
        }
        match self.attr(&path, req) {
            Some(mut attr) => {
                if let Some(len) = size {
                    attr.size = len;
                }
                reply.attr(&WRITE_TTL, &attr);
            }
            None => reply.error(libc::ENOENT),
        }
    }

    /// An empty directory exists only in memory until a file lands beneath it.
    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let path = self.child_of(parent, name);
        if self.node(&path).is_some() {
            reply.error(libc::EEXIST);
            return;
        }
        self.empty_dirs.insert(path.clone());
        match self.attr(&path, req) {
            Some(attr) => reply.entry(&WRITE_TTL, &attr, 0),
            None => reply.error(libc::EIO),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let path = self.child_of(parent, name);
        // A directory the index derives from files cannot be emptied by rmdir.
        if self.fs.is_dir(&path) {
            reply.error(libc::ENOTEMPTY);
            return;
        }
        if !self.empty_dirs.contains(&path) {
            reply.error(libc::ENOENT);
            return;
        }
        let prefix = format!("{path}/");
        if self.empty_dirs.iter().any(|d| d.starts_with(&prefix)) {
            reply.error(libc::ENOTEMPTY);
            return;
        }
        self.empty_dirs.remove(&path);
        self.inodes.forget(&path);
        reply.ok();
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let path = self.child_of(parent, name);
        if self.fs.lookup(&path).is_none() {
            reply.error(libc::ENOENT);
            return;
        }
        FsMut::new(&mut self.index, &self.vault, &mut self.store).unlink(&path);
        self.inodes.forget(&path);
        self.refresh();
        reply.ok();
    }

    /// Moves one file. Renaming a directory (a subtree) is out of scope, matching
    /// [`FsMut::rename`].
    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let from = self.child_of(parent, name);
        let to = self.child_of(newparent, newname);
        let Some((dir, _)) = self.fs.lookup(&from).map(|n| (n.is_dir(), n.size)) else {
            reply.error(libc::ENOENT);
            return;
        };
        if dir {
            reply.error(libc::EISDIR);
            return;
        }
        if !matches!(self.node(Self::parent_of(&to)), Some((true, _))) {
            reply.error(libc::ENOENT);
            return;
        }
        let renamed = FsMut::new(&mut self.index, &self.vault, &mut self.store).rename(&from, &to);
        self.refresh();
        if renamed.is_err() {
            reply.error(libc::EIO);
            return;
        }
        self.inodes.forget(&from);
        reply.ok();
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        // The commit is release's job; there is no half-flushed state.
        reply.ok();
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
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
    use std::sync::{Arc, Mutex};

    use fuser::{spawn_mount2, MountOption};
    use syncbox_crypto::names::DirId;
    use syncbox_crypto::{MasterKey, MasterKeys};
    use syncbox_index::{FileEntry, MemoryIndex};
    use syncbox_mount::{Fs, FsMut, MemoryStore};

    use super::*;

    fn keys() -> MasterKeys {
        MasterKeys {
            primary: MasterKey::from_bytes(&[0x20; 32]).unwrap(),
            hmac: MasterKey::from_bytes(&[0x00; 32]).unwrap(),
        }
    }

    /// Real mounts are serialized: establishing two FUSE mounts concurrently in one
    /// process races inside fusermount3's handshake (`fstat of comm fd` fails as
    /// the two fork-and-exec launches touch shared fds), failing a mount before the
    /// filesystem sees any request. A mutex, not a fix in us — our code is nowhere
    /// on that path. `into_inner` on a poison just means another mount test died.
    static MOUNT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn mount_gate() -> std::sync::MutexGuard<'static, ()> {
        MOUNT_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // --- pure helpers ---------------------------------------------------------

    #[test]
    fn patch_fills_grows_and_overwrites() {
        let mut buf = b"hello".to_vec();
        patch(&mut buf, 6, b"world");
        assert_eq!(&buf, b"hello\0world");
        patch(&mut buf, 0, b"HE");
        assert_eq!(&buf, b"HEllo\0world");
    }

    #[test]
    fn list_dir_merges_empty_dirs_without_duplicates() {
        let entry = |path: &str| FileEntry::fresh(path, DirId::from_base32("AA"), "C");
        let mut index = MemoryIndex::default();
        index.put_file(entry("docs/kept.txt"));
        let fs = Fs::from_index(&index);
        let empty: BTreeSet<String> = ["docs", "vacant", "deep/nest"]
            .into_iter()
            .map(str::to_owned)
            .collect();

        let root = list_dir(&fs, &empty, "").expect("root");
        let names: Vec<&str> = root.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["deep", "docs", "vacant"]);

        // `docs` exists both in the index (as a file prefix) and in the empty set,
        // and is listed once.
        let docs = list_dir(&fs, &empty, "docs").expect("docs");
        let names: Vec<&str> = docs.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["kept.txt"]);

        let deep = list_dir(&fs, &empty, "deep").expect("deep");
        assert_eq!(deep[0].name, "nest");
    }

    #[test]
    fn inodes_are_stable_and_forgotten_with_their_path() {
        let mut inodes = Inodes::new();
        let a = inodes.ensure("a.txt");
        assert_eq!(inodes.ensure("a.txt"), a, "stable while known");
        inodes.forget("a.txt");
        assert_ne!(
            inodes.ensure("a.txt"),
            a,
            "a re-created file is a new inode"
        );
    }

    // --- shared handles: a WritableFS the test can still see through ----------

    /// An [`Index`] sharing a [`MemoryIndex`] behind `Arc<Mutex<..>>`, so the test
    /// keeps a handle after the mount takes ownership of its clone.
    #[derive(Clone, Default)]
    struct SharedIndex(Arc<Mutex<MemoryIndex>>);

    impl Index for SharedIndex {
        fn file(&self, path: &str) -> Option<FileEntry> {
            self.0.lock().unwrap().file(path)
        }
        fn files(&self) -> Vec<FileEntry> {
            self.0.lock().unwrap().files()
        }
        fn put_file(&mut self, entry: FileEntry) {
            self.0.lock().unwrap().put_file(entry);
        }
        fn remove_file(&mut self, path: &str) -> bool {
            self.0.lock().unwrap().remove_file(path)
        }
        fn retain_chunk(&mut self, id: &syncbox_crypto::ChunkId, size: u64) {
            self.0.lock().unwrap().retain_chunk(id, size);
        }
        fn release_chunk(&mut self, id: &syncbox_crypto::ChunkId) {
            self.0.lock().unwrap().release_chunk(id);
        }
        fn chunk_refs(&self, id: &syncbox_crypto::ChunkId) -> u32 {
            self.0.lock().unwrap().chunk_refs(id)
        }
        fn unreferenced_chunks(&self) -> Vec<syncbox_crypto::ChunkId> {
            self.0.lock().unwrap().unreferenced_chunks()
        }
        fn referenced_bytes(&self) -> u64 {
            self.0.lock().unwrap().referenced_bytes()
        }
        fn note_delete(&mut self, entry: &FileEntry) {
            self.0.lock().unwrap().note_delete(entry);
        }
        fn pending_deletes(&self) -> Vec<syncbox_index::DeletedFile> {
            self.0.lock().unwrap().pending_deletes()
        }
        fn clear_deletes(&mut self, keys: &[(syncbox_crypto::names::DirId, String)]) {
            self.0.lock().unwrap().clear_deletes(keys);
        }
        fn meta_value(&self, key: &str) -> Option<String> {
            self.0.lock().unwrap().meta_value(key)
        }
        fn set_meta_value(&mut self, key: &str, value: &str) {
            self.0.lock().unwrap().set_meta_value(key, value);
        }
    }

    /// A [`WriteStore`] sharing a [`MemoryStore`] behind `Arc<Mutex<..>>`.
    #[derive(Clone, Default)]
    struct SharedStore(Arc<Mutex<MemoryStore>>);

    impl ContentStore for SharedStore {
        fn manifest(&self, dir_id: &DirId, cipher_name: &str) -> Option<Vec<u8>> {
            self.0.lock().unwrap().manifest(dir_id, cipher_name)
        }
        fn chunk(&self, id: &syncbox_crypto::ChunkId) -> Option<Vec<u8>> {
            self.0.lock().unwrap().chunk(id)
        }
    }

    impl WriteStore for SharedStore {
        fn put_chunk(&mut self, id: &syncbox_crypto::ChunkId, bytes: &[u8]) -> std::io::Result<()> {
            self.0.lock().unwrap().put_chunk(id, bytes)
        }
        fn put_manifest(
            &mut self,
            dir_id: &DirId,
            cipher_name: &str,
            bytes: &[u8],
        ) -> std::io::Result<()> {
            self.0
                .lock()
                .unwrap()
                .put_manifest(dir_id, cipher_name, bytes)
        }
    }

    // --- real mounts ----------------------------------------------------------

    /// Mounts a vault staged with two files and reads it back through a real FUSE
    /// mount. Ignored by default (needs a FUSE driver); run with
    /// `cargo test -p syncbox-cli --features mount -- --ignored`.
    #[test]
    #[ignore = "requires a FUSE driver (/dev/fuse, fusermount3)"]
    fn a_real_readonly_mount_serves_the_staged_files() {
        let _serial = mount_gate();
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
            std::time::Duration::from_secs(5),
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

        // A read-only mount refuses writes at the kernel before they reach us.
        let denied = std::fs::write(root.join("nope.txt"), b"x");
        assert!(denied.is_err(), "an RO mount is not writable");

        session.join();
    }

    #[test]
    #[ignore = "requires a FUSE driver (/dev/fuse, fusermount3)"]
    fn a_real_writable_mount_edits_the_vault_in_place() {
        let _serial = mount_gate();
        let mountpoint = tempfile::tempdir().unwrap();
        let scratch = tempfile::tempdir().unwrap();

        // The mount owns its index and store; the test watches through shared handles
        // (the CLI equivalent is the live SqliteIndex + DiskStore).
        let index = SharedIndex::default();
        let store = SharedStore::default();
        let vault = Vault::new(keys(), "vault", scratch.path()).expect("vault");
        {
            let mut stage_index = index.clone();
            let mut stage_store = store.clone();
            let mut fs = FsMut::new(&mut stage_index, &vault, &mut stage_store);
            fs.write("old.txt", b"original content").expect("stage old");
        }

        let view = WritableFS::new(index.clone(), vault, store.clone());
        let session = spawn_mount2(
            view,
            mountpoint.path(),
            &[
                MountOption::FSName("syncbox".to_owned()),
                MountOption::DefaultPermissions,
            ],
        )
        .expect("mount");
        let root = mountpoint.path();
        wait_until(
            || root.join("old.txt").exists(),
            std::time::Duration::from_secs(5),
        )
        .expect("mount became ready");

        // Create + close is the commit; the bytes read straight back.
        std::fs::write(root.join("new.txt"), b"first version").expect("create");
        assert_eq!(
            std::fs::read(root.join("new.txt")).unwrap(),
            b"first version"
        );

        // Overwrite through the mount (O_TRUNC open, whole-file rewrite).
        std::fs::write(root.join("new.txt"), b"second version, shorter").expect("overwrite");
        assert_eq!(
            std::fs::read(root.join("new.txt")).unwrap(),
            b"second version, shorter"
        );

        // Directories: mkdir alone is in-memory; a file beneath it persists normally.
        std::fs::create_dir(root.join("docs")).expect("mkdir");
        std::fs::write(root.join("docs/inner.txt"), b"nested").expect("inner");
        assert!(root.join("docs").is_dir());

        // Rename and delete.
        std::fs::rename(root.join("docs/inner.txt"), root.join("docs/renamed.txt"))
            .expect("rename");
        std::fs::remove_file(root.join("old.txt")).expect("remove");

        let mut names: Vec<String> = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["docs".to_owned(), "new.txt".to_owned()]);

        session.join();

        // What the vault holds after unmounting: the edit is a sealed, *dirty* index
        // record — exactly what a sync push will pick up — not a plaintext file.
        let entry = index.file("new.txt").expect("new.txt is indexed");
        assert!(entry.local_dirty, "a mount write is sync-able");
        let verifier = Vault::new(keys(), "vault", scratch.path()).expect("vault");
        let fs = Fs::from_index(&index);
        assert_eq!(
            fs.read_all(&verifier, &store, "new.txt")
                .expect("read back"),
            b"second version, shorter"
        );
        assert_eq!(
            fs.read_all(&verifier, &store, "docs/renamed.txt")
                .expect("renamed"),
            b"nested"
        );
        assert!(
            index.file("old.txt").is_none(),
            "the delete reached the index"
        );
        assert!(
            index.file("docs/inner.txt").is_none(),
            "rename moved the record"
        );
    }

    fn wait_until<F: Fn() -> bool>(pred: F, timeout: std::time::Duration) -> Option<()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if pred() {
                return Some(());
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}
