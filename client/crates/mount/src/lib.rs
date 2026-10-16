//! A vault seen as a filesystem, with no kernel and no crypto in the hot path.
//!
//! The FUSE mount is really two things. The hard, interesting thing — deciding what
//! the tree *is* — lives here; the [`fuser`] adapter that hands those answers to the
//! kernel is a thin mapping kept in a separate crate so this one needs no libfuse.
//!
//! The namespace is the local [`Index`], not the ciphertext. Directory names cannot
//! be recovered from the server's opaque ids alone (a subdirectory's encrypted name is
//! never stored under its parent), so the client's own index — which records
//! [`FileEntry`] plaintext paths — is the only place the tree's shape is knowable. A
//! path is a file when the index has an entry for it, and a directory when it is the
//! parent prefix of some entry. Content itself is not read here; that needs the
//! per-file manifest and chunks and is the [`ContentStore`] step.
//!
//! [`fuser`]: https://docs.rs/fuser

use std::collections::{BTreeMap, BTreeSet};

use syncbox_index::{FileEntry, Index};

/// Whether a path names a directory or a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    /// A directory (including the root).
    Directory,
    /// A regular file.
    File,
}

/// A node in the vault tree: enough to answer `getattr`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// Normalised path, `""` for the root.
    pub path: String,
    /// Directory or file.
    pub kind: NodeKind,
    /// Byte size (0 for a directory).
    pub size: u64,
    /// The revision a file corresponds to (0 for a directory or an unsynced file).
    pub revision: u64,
}

impl Node {
    /// The root directory.
    #[must_use]
    pub fn root() -> Self {
        Self {
            path: String::new(),
            kind: NodeKind::Directory,
            size: 0,
            revision: 0,
        }
    }

    /// True for a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.kind == NodeKind::Directory
    }
}

/// One child of a directory, as `readdir` reports it. The `.` and `..` entries are
/// left to the caller (FUSE synthesises them), so the list holds only real children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The child's basename.
    pub name: String,
    /// Directory or file.
    pub kind: NodeKind,
    /// Byte size (0 for a directory).
    pub size: u64,
}

/// A read-only snapshot of the vault tree built from an [`Index`].
///
/// It is a value, not a live handle: the mount takes a snapshot per operation (or
/// after each sync) so the filesystem it presents is stable while a directory read is
/// in flight. Rebuilding it from the index is cheap.
#[derive(Debug, Default, Clone)]
pub struct Fs {
    files: BTreeMap<String, Node>,
    /// Every directory path; the root `""` is always present.
    dirs: BTreeSet<String>,
}

impl Fs {
    /// An empty tree: just the root directory.
    #[must_use]
    pub fn empty() -> Self {
        let mut dirs = BTreeSet::new();
        dirs.insert(String::new());
        Self {
            files: BTreeMap::new(),
            dirs,
        }
    }

    /// Builds the tree from everything the index knows.
    #[must_use]
    pub fn from_index(index: &dyn Index) -> Self {
        Self::from_entries(index.files().iter())
    }

    /// Builds the tree from a set of file records (the index's, or a test's).
    #[must_use]
    pub fn from_entries<'a>(entries: impl Iterator<Item = &'a FileEntry>) -> Self {
        let mut fs = Self::empty();
        for entry in entries {
            fs.add_file(&entry.path, entry.size, entry.revision);
        }
        fs
    }

    /// Records a file and turns every ancestor prefix into a directory.
    fn add_file(&mut self, raw_path: &str, size: u64, revision: u64) {
        let path = normalize(raw_path);
        if path.is_empty() {
            return;
        }
        let components: Vec<&str> = path.split('/').collect();
        // Every component except the last names a directory that must exist.
        let mut acc = String::new();
        for component in &components[..components.len() - 1] {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(component);
            // A prefix that is itself a recorded file is a corrupt index; skip it
            // rather than list the same path twice.
            if !self.files.contains_key(&acc) {
                self.dirs.insert(acc.clone());
            }
        }
        self.dirs.remove(&path);
        self.files.insert(
            path.clone(),
            Node {
                path,
                kind: NodeKind::File,
                size,
                revision,
            },
        );
    }

    /// The node at `path`, or `None` if nothing is there. `""` and `"/"` are the root.
    #[must_use]
    pub fn lookup(&self, path: &str) -> Option<Node> {
        let path = normalize(path);
        if path.is_empty() {
            return Some(Node::root());
        }
        if let Some(node) = self.files.get(&path) {
            return Some(node.clone());
        }
        if self.dirs.contains(&path) {
            return Some(Node {
                path,
                kind: NodeKind::Directory,
                size: 0,
                revision: 0,
            });
        }
        None
    }

    /// The real children of the directory `path`, sorted by name. `None` if `path` is
    /// not a directory.
    #[must_use]
    pub fn readdir(&self, path: &str) -> Option<Vec<DirEntry>> {
        let dir = normalize(path);
        if !(dir.is_empty() || self.dirs.contains(&dir)) {
            return None;
        }
        let mut children = Vec::new();
        for (child_path, node) in &self.files {
            if parent_of(child_path) == dir {
                children.push(DirEntry {
                    name: basename(child_path).to_owned(),
                    kind: NodeKind::File,
                    size: node.size,
                });
            }
        }
        for child_dir in &self.dirs {
            if !child_dir.is_empty() && parent_of(child_dir) == dir {
                children.push(DirEntry {
                    name: basename(child_dir).to_owned(),
                    kind: NodeKind::Directory,
                    size: 0,
                });
            }
        }
        children.sort_by(|a, b| a.name.cmp(&b.name));
        Some(children)
    }

    /// True when `path` names a directory (the root included).
    #[must_use]
    pub fn is_dir(&self, path: &str) -> bool {
        let path = normalize(path);
        path.is_empty() || self.dirs.contains(&path)
    }

    /// True when the tree holds nothing but the root.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.dirs.len() == 1
    }

    /// Every file path, sorted. Handy for tests and for a `find`-style view.
    #[must_use]
    pub fn file_paths(&self) -> Vec<String> {
        self.files.keys().cloned().collect()
    }
}

/// Collapses a path to its canonical form: `/`-joined, no leading/trailing or
/// repeated slashes, no `.` segments. Returns `""` for the root.
fn normalize(path: &str) -> String {
    path.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// The directory that holds `path`, or `""` for a top-level entry.
fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) => &path[..index],
        None => "",
    }
}

/// The final path component.
fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) => &path[index + 1..],
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use syncbox_crypto::names::DirId;
    use syncbox_index::MemoryIndex;

    use super::*;

    fn entry(path: &str, size: u64, revision: u64) -> FileEntry {
        FileEntry {
            revision,
            size,
            ..FileEntry::fresh(path, DirId::from_base32("AA"), "CIPHER")
        }
    }

    fn sample() -> Fs {
        let files = [
            entry("a.txt", 10, 3),
            entry("docs/readme.md", 200, 5),
            entry("docs/sub/deep.bin", 1_024, 7),
        ];
        Fs::from_entries(files.iter())
    }

    #[test]
    fn empty_tree_is_just_the_root() {
        let fs = Fs::empty();
        assert!(fs.is_empty());
        assert_eq!(fs.lookup("").map(|n| n.kind), Some(NodeKind::Directory));
        assert_eq!(fs.lookup("/").map(|n| n.kind), Some(NodeKind::Directory));
        assert_eq!(fs.readdir("").unwrap(), vec![]);
        assert_eq!(fs.lookup("anything"), None);
    }

    #[test]
    fn a_file_node_carries_its_size_and_revision() {
        let fs = sample();
        let node = fs.lookup("a.txt").expect("file");
        assert_eq!(node.kind, NodeKind::File);
        assert_eq!(node.size, 10);
        assert_eq!(node.revision, 3);
    }

    #[test]
    fn directories_come_from_path_prefixes_not_entries() {
        let fs = sample();
        // "docs" and "docs/sub" were never entered as files; they exist because a
        // path runs through them.
        assert_eq!(fs.lookup("docs").map(|n| n.kind), Some(NodeKind::Directory));
        assert_eq!(
            fs.lookup("docs/sub").map(|n| n.kind),
            Some(NodeKind::Directory)
        );
        assert!(fs.is_dir("docs"));
        assert!(!fs.is_dir("a.txt"));
    }

    #[test]
    fn root_listing_sorts_files_and_dirs_by_name() {
        let fs = sample();
        let entries = fs.readdir("").unwrap();
        assert_eq!(
            names(&entries),
            vec!["a.txt", "docs"],
            "top level is a file and one directory"
        );
        assert_eq!(entries[0].kind, NodeKind::File);
        assert_eq!(entries[1].kind, NodeKind::Directory);
    }

    #[test]
    fn nested_readdir_sees_only_direct_children() {
        let fs = sample();
        assert_eq!(
            names(&fs.readdir("docs").unwrap()),
            vec!["readme.md", "sub"]
        );
        assert_eq!(names(&fs.readdir("docs/sub").unwrap()), vec!["deep.bin"]);
        assert!(
            fs.readdir("docs/sub/deep.bin").is_none(),
            "a file is not a directory"
        );
    }

    #[test]
    fn looking_up_beyond_the_tree_is_none() {
        let fs = sample();
        assert_eq!(fs.lookup("nope"), None);
        assert_eq!(fs.lookup("docs/nope/x"), None);
        assert!(
            fs.readdir("nope").is_none(),
            "listing a non-directory fails"
        );
    }

    #[test]
    fn paths_are_normalized_for_slashes_and_dots() {
        let fs = sample();
        assert_eq!(
            fs.lookup("/docs//sub/").map(|n| n.path),
            Some("docs/sub".into())
        );
        assert_eq!(fs.lookup("./a.txt").map(|n| n.size), Some(10));
    }

    #[test]
    fn file_paths_are_sorted() {
        let fs = sample();
        assert_eq!(
            fs.file_paths(),
            vec!["a.txt", "docs/readme.md", "docs/sub/deep.bin"]
        );
    }

    #[test]
    fn it_builds_from_a_real_index() {
        let mut index = MemoryIndex::default();
        index.put_file(entry("notes.txt", 7, 1));
        index.put_file(entry("img/logo.png", 42, 2));
        let fs = Fs::from_index(&index);
        assert_eq!(names(&fs.readdir("").unwrap()), vec!["img", "notes.txt"]);
        assert_eq!(fs.lookup("img/logo.png").map(|n| n.size), Some(42));
    }

    fn names(entries: &[DirEntry]) -> Vec<String> {
        entries.iter().map(|e| e.name.clone()).collect()
    }
}
