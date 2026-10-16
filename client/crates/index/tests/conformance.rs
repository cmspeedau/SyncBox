//! The two `Index` implementations must agree. Whatever the engine codes against
//! is the `Index` trait, so any divergence between the RAM index the tests use and
//! the SQLite index the client ships with is a bug that only surfaces after a
//! crash-and-resume. This suite runs one set of invariants against both.

use syncbox_crypto::names::{base32_encode, DirId};
use syncbox_crypto::ChunkId;
use syncbox_index::{FileEntry, Index, MemoryIndex, SqliteIndex};

fn chunk(tag: u8) -> ChunkId {
    ChunkId::from_base32(&base32_encode(&[tag]))
}

fn entry(path: &str, chunks: &[u8]) -> FileEntry {
    FileEntry {
        path: path.to_owned(),
        dir_id: DirId::from_base32("AA"),
        cipher_name: format!("{path}.c9r"),
        size: chunks.len() as u64 * 1024,
        modified_unix: 1_700_000_000,
        revision: 1,
        chunk_ids: chunks.iter().map(|t| chunk(*t)).collect(),
        local_dirty: false,
        remote_dirty: false,
    }
}

fn files_are_sorted_by_path(index: &mut dyn Index) {
    index.put_file(entry("z.txt", &[]));
    index.put_file(entry("a.txt", &[]));
    index.put_file(entry("m.txt", &[]));
    let paths: Vec<String> = index.files().into_iter().map(|e| e.path).collect();
    assert_eq!(paths, vec!["a.txt", "m.txt", "z.txt"]);
}

fn a_file_round_trips_every_field(index: &mut dyn Index) {
    let original = FileEntry {
        path: "deep/notes.txt".into(),
        dir_id: DirId::from_base32("ABCDEFGH"),
        cipher_name: "VQAF7BFK".into(),
        size: 12_345,
        modified_unix: -5,
        revision: 42,
        chunk_ids: vec![chunk(1), chunk(2), chunk(3)],
        local_dirty: true,
        remote_dirty: false,
    };
    index.put_file(original.clone());
    let back = index.file("deep/notes.txt").expect("file present");
    assert_eq!(back, original, "every field and the chunk order survive");
}

fn rewriting_drops_only_the_chunks_it_stopped_using(index: &mut dyn Index) {
    let kept = chunk(2);
    let dropped = chunk(1);
    let added = chunk(3);

    index.put_file(entry("notes.txt", &[1, 2]));
    assert_eq!(index.chunk_refs(&kept), 1);
    assert_eq!(index.chunk_refs(&dropped), 1);

    index.put_file(entry("notes.txt", &[2, 3]));
    assert_eq!(index.chunk_refs(&kept), 1, "kept chunk keeps one reference");
    assert_eq!(index.chunk_refs(&dropped), 0, "dropped chunk dies");
    assert_eq!(index.chunk_refs(&added), 1, "new chunk lives");
    assert!(index.unreferenced_chunks().contains(&dropped));
    assert!(!index.unreferenced_chunks().contains(&kept));
    assert_eq!(index.file("notes.txt").unwrap().chunk_ids.len(), 2);
}

fn a_shared_chunk_survives_one_file_being_deleted(index: &mut dyn Index) {
    let shared = chunk(9);
    index.put_file(FileEntry {
        chunk_ids: vec![shared.clone()],
        ..entry("a.txt", &[])
    });
    index.put_file(FileEntry {
        chunk_ids: vec![shared.clone()],
        ..entry("b.txt", &[])
    });
    assert_eq!(index.chunk_refs(&shared), 2);

    assert!(index.remove_file("a.txt"));
    assert_eq!(index.chunk_refs(&shared), 1);
    assert!(
        !index.unreferenced_chunks().contains(&shared),
        "still referenced by b.txt"
    );

    assert!(index.remove_file("b.txt"));
    assert_eq!(index.chunk_refs(&shared), 0);
    assert!(index.unreferenced_chunks().contains(&shared));
}

fn removing_an_unknown_file_reports_nothing_removed(index: &mut dyn Index) {
    assert!(!index.remove_file("ghost.txt"));
}

fn sizes_are_recorded_once_and_bytes_sum_over_referenced_chunks(index: &mut dyn Index) {
    let id = chunk(5);
    index.retain_chunk(&id, 4096);
    index.retain_chunk(&id, 4096);
    assert_eq!(index.referenced_bytes(), 4096, "counted once, not twice");
    index.release_chunk(&id);
    assert_eq!(index.referenced_bytes(), 4096);
    index.release_chunk(&id);
    assert_eq!(index.referenced_bytes(), 0);
}

fn releasing_more_than_retaining_does_not_panic(index: &mut dyn Index) {
    let id = chunk(7);
    index.release_chunk(&id);
    assert_eq!(index.chunk_refs(&id), 0, "the count bottoms out at zero");
}

fn the_trait_is_usable_as_a_trait_object(index: &mut dyn Index) {
    assert!(index.files().is_empty());
    index.put_file(entry("solo.txt", &[1]));
    assert_eq!(index.files().len(), 1);
}

fn deletes_queue_a_tombstone_until_committed(index: &mut dyn Index) {
    let gone = entry("gone.txt", &[1]);
    index.put_file(gone.clone());
    index.remove_file("gone.txt");
    assert!(
        index.pending_deletes().is_empty(),
        "a plain remove_file owes the server nothing"
    );

    index.note_delete(&gone);
    index.remove_file("gone.txt");
    let queued = index.pending_deletes();
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].path, "gone.txt", "the path survives for display");
    assert_eq!(queued[0].key().1, "gone.txt.c9r", "the key is the server's");

    index.note_delete(&gone);
    assert_eq!(
        index.pending_deletes().len(),
        1,
        "the same key collapses to one entry"
    );

    index.note_delete(&entry("other.txt", &[2]));
    assert_eq!(index.pending_deletes().len(), 2);

    index.clear_deletes(&[(gone.dir_id.clone(), gone.cipher_name.clone())]);
    let rest = index.pending_deletes();
    assert_eq!(rest.len(), 1, "only the committed tombstone is dropped");
    assert_eq!(rest[0].path, "other.txt");
}

/// The whole contract, each invariant run against a freshly built backend so the
/// checks are independent (and a chunk id reused by two checks stays meaningful).
fn conformance(make: impl Fn() -> Box<dyn Index>) {
    files_are_sorted_by_path(&mut *make());
    a_file_round_trips_every_field(&mut *make());
    rewriting_drops_only_the_chunks_it_stopped_using(&mut *make());
    a_shared_chunk_survives_one_file_being_deleted(&mut *make());
    removing_an_unknown_file_reports_nothing_removed(&mut *make());
    sizes_are_recorded_once_and_bytes_sum_over_referenced_chunks(&mut *make());
    releasing_more_than_retaining_does_not_panic(&mut *make());
    deletes_queue_a_tombstone_until_committed(&mut *make());
}

#[test]
fn memory_index_satisfies_the_contract() {
    conformance(|| -> Box<dyn Index> { Box::new(MemoryIndex::new()) });
    the_trait_is_usable_as_a_trait_object(&mut MemoryIndex::new());
}

#[test]
fn sqlite_index_satisfies_the_contract() {
    conformance(|| -> Box<dyn Index> { Box::new(SqliteIndex::open_in_memory()) });
    the_trait_is_usable_as_a_trait_object(&mut SqliteIndex::open_in_memory());
}

#[test]
fn sqlite_index_survives_being_closed_and_reopened() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("index.db");
    let shared = chunk(9);

    {
        let mut index = SqliteIndex::open(&db).expect("create index");
        index.put_file(entry("keep.txt", &[1, 2, 3]));
        index.retain_chunk(&shared, 8192);
        index.note_delete(&entry("gone.txt", &[4]));
    }

    let index = SqliteIndex::open(&db).expect("reopen index");
    assert_eq!(index.file("keep.txt").unwrap().chunk_ids.len(), 3);
    assert_eq!(
        index
            .pending_deletes()
            .iter()
            .map(|d| &d.path)
            .collect::<Vec<_>>(),
        vec!["gone.txt"],
        "an uncommitted tombstone survives the crash"
    );
    assert_eq!(index.chunk_refs(&shared), 1);
    assert_eq!(index.referenced_bytes(), 8192);
}
