//! Splitting plaintext into chunks.
//!
//! Boundary choice is the whole reason Syncbox can sync a changed 4 GiB file in
//! seconds. A fixed-size splitter shifts every boundary after an insertion, so
//! the server is told that everything after byte 12 is new. A content-defined
//! splitter looks at the bytes and lands on the same boundaries regardless of
//! what happened earlier in the file, so only the chunks the edit actually
//! touched have to travel.

use syncbox_crypto::content::{CHUNK_MAX, CHUNK_MIN, CHUNK_TARGET};

use crate::error::{Result, SyncError};
use std::sync::OnceLock;

/// Bytes pulled per fill of [`FastCdc::split_stream`] — I/O granularity, not a
/// format parameter: boundaries cannot depend on it, and the equivalence tests
/// prove they do not.
const STREAM_FILL: usize = 128 * 1024;

/// A half-open byte range of plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    /// First byte of the chunk.
    pub start: usize,
    /// One past the last byte of the chunk.
    pub end: usize,
}

impl Chunk {
    /// A chunk covering `start` up to but not including `end`.
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    /// Number of plaintext bytes in the chunk.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    /// True for an empty range, which only occurs for a zero-byte file.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Cuts this chunk out of a buffer.
    #[must_use]
    pub fn slice<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        let start = self.start.min(data.len());
        let end = self.end.min(data.len()).max(start);
        &data[start..end]
    }
}

/// Chooses chunk boundaries for one file at a time.
///
/// A chunker carries rolling state, so it is `&mut self` and has [`Chunker::reset`]
/// for when the next file starts.
pub trait Chunker {
    /// Boundaries for `data`, in order and without gaps.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::ChunkTooLarge`] if the splitter would exceed what the
    /// format stores.
    fn split(&mut self, data: &[u8]) -> Result<Vec<Chunk>>;

    /// Forgets any state carried from the previous file.
    fn reset(&mut self);
}

/// The gear table: 256 random 64-bit values, one per input byte.
///
/// Generated deterministically from a fixed seed the first time it is needed, so
/// every Syncbox build — and every other conforming implementation that fixes the
/// same seed — lands on the same boundaries for the same bytes. A table shared by
/// the whole process is built once.
fn gear_table() -> &'static [u64; 256] {
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u64; 256];
        // SplitMix64 is tiny and deterministic; only reproducibility matters here.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for slot in &mut table {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *slot = z ^ (z >> 31);
        }
        table
    })
}

/// The content-defined splitter Syncbox ships.
///
/// Boundaries come from a rolling gear hash over the input, clamped to
/// [`CHUNK_MIN`] and [`CHUNK_MAX`] and aiming at [`CHUNK_TARGET`] via normalized
/// chunking: below the target the cut mask is hard to satisfy so chunks keep
/// growing, above it the mask is easy so a boundary is found soon. The result is an
/// average chunk size near the target that depends only on the bytes, so an edit
/// re-splits only the region around it and everything else keeps its content
/// address.
#[derive(Clone, Copy, Debug)]
pub struct FastCdc {
    /// Smallest chunk emitted.
    pub min: usize,
    /// Size the rolling hash aims for.
    pub target: usize,
    /// Largest chunk emitted.
    pub max: usize,
}

impl Default for FastCdc {
    fn default() -> Self {
        Self {
            min: CHUNK_MIN,
            target: CHUNK_TARGET,
            max: CHUNK_MAX,
        }
    }
}

impl FastCdc {
    /// A splitter with the format's default sizes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Splits a reader, handing each finished chunk's bytes to `on_chunk` as soon
    /// as it is complete, so a 4 GiB file costs one chunk of memory, not four.
    ///
    /// The boundaries are byte-for-byte those [`Chunker::split`] would produce for
    /// the same bytes — the rolling hash is forward-only and resets at every chunk,
    /// so no look-ahead is needed — which is what keeps content addresses stable
    /// between the buffered and streaming paths, and between clients that took
    /// different routes to the same content.
    ///
    /// Returns the number of chunks emitted. An empty reader emits none, matching
    /// [`Chunker::split`] on empty input.
    ///
    /// # Errors
    ///
    /// Propagates reader I/O, configuration, and [`on_chunk`] errors.
    pub fn split_stream<R, F>(&mut self, reader: &mut R, mut on_chunk: F) -> Result<usize>
    where
        R: std::io::Read,
        F: FnMut(&[u8]) -> Result<()>,
    {
        if !self.is_valid() {
            return Err(SyncError::ChunkTooLarge {
                actual: self.max,
                limit: self.min,
            });
        }

        let gear = gear_table();
        let (hard, easy) = self.masks();
        let mut buf: Vec<u8> = Vec::with_capacity(self.max + STREAM_FILL);
        let mut start = 0usize; // the unfinished chunk begins here
        let mut scan = 0usize; // next byte to feed the hash
        let mut hash = 0u64;
        let mut warmed = false; // the minimum region of the current chunk is fed
        let mut eof = false;
        let mut emitted = 0usize;
        let mut scratch = vec![0u8; STREAM_FILL];

        loop {
            if eof && start == buf.len() {
                return Ok(emitted);
            }

            // The tail rule, mirrored from split(): a remainder no longer than the
            // minimum is one chunk, hashed or not — and only at EOF, because only
            // EOF proves it is the remainder.
            if eof && buf.len() - start <= self.min {
                if buf.len() > start {
                    on_chunk(&buf[start..])?;
                    emitted += 1;
                }
                buf.clear();
                start = 0;
                hash = 0;
                warmed = false;
                continue;
            }

            if !warmed {
                if buf.len() - start < self.min {
                    // Not even a minimum has arrived yet: read, then re-check —
                    // EOF turns this same remainder into the tail above.
                    if !eof {
                        match reader.read(&mut scratch) {
                            Ok(0) => eof = true,
                            Ok(n) => buf.extend_from_slice(&scratch[..n]),
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                            Err(e) => return Err(SyncError::Io(e)),
                        }
                    }
                    continue;
                }
                for &byte in &buf[start..start + self.min] {
                    hash = hash.wrapping_shl(1).wrapping_add(gear[usize::from(byte)]);
                }
                scan = start + self.min;
                warmed = true;
            }

            // Feed one byte at a time, exactly as split() does, cutting at the
            // first mask hit — the triggering byte belongs to the NEXT chunk,
            // because split() breaks before advancing past it.
            let cap = (start + self.max).min(buf.len());
            let mut cut = None;
            while scan < cap {
                hash = hash
                    .wrapping_shl(1)
                    .wrapping_add(gear[usize::from(buf[scan])]);
                let mask = if scan < start + self.target {
                    hard
                } else {
                    easy
                };
                if hash & mask == 0 {
                    cut = Some(scan);
                    break;
                }
                scan += 1;
            }

            let end = match cut {
                Some(end) => end,
                None if scan >= start + self.max => scan, // clamped to the maximum
                None if eof => buf.len(), // ran out of file before a cut: the whole remainder
                None => {
                    // Buffer exhausted short of the maximum with more to come:
                    // keep the hash state and read on.
                    match reader.read(&mut scratch) {
                        Ok(0) => eof = true,
                        Ok(n) => buf.extend_from_slice(&scratch[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(SyncError::Io(e)),
                    }
                    continue;
                }
            };

            if end > start {
                on_chunk(&buf[start..end])?;
                emitted += 1;
            }
            buf.drain(..end);
            start = 0;
            hash = 0;
            warmed = false;
        }
    }

    /// True when the configuration is usable: the minimum has to sit under the
    /// maximum, or the clamp could not produce anything valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.min > 0 && self.min < self.target && self.target < self.max
    }

    /// The two normalized-chunking masks, derived from the target size. `hard` is
    /// used below the target (more bits set → a cut is rarer → chunks grow), `easy`
    /// above it (fewer bits → a cut comes soon).
    fn masks(&self) -> (u64, u64) {
        // bits = ceil(log2(target)); clamp to a range where 1<<bits stays inside u64.
        let bits = usize::BITS - self.target.leading_zeros();
        let bits = bits.clamp(2, 62);
        let hard = (1u64 << (bits + 1)) - 1;
        let easy = (1u64 << (bits - 1)) - 1;
        (hard, easy)
    }
}

impl Chunker for FastCdc {
    fn split(&mut self, data: &[u8]) -> Result<Vec<Chunk>> {
        if !self.is_valid() {
            return Err(SyncError::ChunkTooLarge {
                actual: self.max,
                limit: self.min,
            });
        }
        if data.is_empty() {
            // An empty file has no chunks, which the engine uses to tell "empty"
            // apart from "not yet chunked".
            return Ok(Vec::new());
        }

        let gear = gear_table();
        let (hard, easy) = self.masks();
        let n = data.len();
        let mut chunks = Vec::new();
        let mut start = 0usize;

        while start < n {
            // A tail shorter than the minimum stays as one chunk: padding it to
            // the minimum would merge it with a neighbour it does not belong to.
            if n - start <= self.min {
                chunks.push(Chunk::new(start, n));
                break;
            }

            // Warm the rolling hash across the minimum region, where no cut is
            // allowed, so the hash reflects the chunk's contents before we look.
            let mut hash = 0u64;
            for &byte in &data[start..start + self.min] {
                hash = hash.wrapping_shl(1).wrapping_add(gear[usize::from(byte)]);
            }

            let search_end = start + self.max; // never cut past the maximum
            let mut i = start + self.min;
            while i < search_end && i < n {
                hash = hash
                    .wrapping_shl(1)
                    .wrapping_add(gear[usize::from(data[i])]);
                let mask = if i < start + self.target { hard } else { easy };
                if hash & mask == 0 {
                    break;
                }
                i += 1;
            }

            let end = i.min(n);
            chunks.push(Chunk::new(start, end));
            start = end;
        }

        Ok(chunks)
    }

    fn reset(&mut self) {}
}

/// A fixed-size splitter.
///
/// This is not what Syncbox stores — see the module comment — but it is real, it
/// exercises everything downstream of the splitter, and it is what the chunking
/// contract is tested against until [`FastCdc`] is finished.
#[derive(Clone, Copy, Debug)]
pub struct FixedSize {
    /// Bytes per chunk, except possibly the last.
    pub size: usize,
}

impl FixedSize {
    /// A splitter with the given fixed size. A size of zero is treated as one so
    /// splitting cannot spin forever.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self { size: size.max(1) }
    }
}

impl Default for FixedSize {
    fn default() -> Self {
        Self::new(CHUNK_TARGET)
    }
}

impl Chunker for FixedSize {
    fn split(&mut self, data: &[u8]) -> Result<Vec<Chunk>> {
        if data.is_empty() {
            // An empty file has no chunks at all, which the engine relies on to
            // tell "empty" apart from "not yet chunked".
            return Ok(Vec::new());
        }
        Ok(data
            .chunks(self.size)
            .enumerate()
            .map(|(i, part)| Chunk::new(i * self.size, i * self.size + part.len()))
            .collect())
    }

    fn reset(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(chunks: &[Chunk]) -> Vec<(usize, usize)> {
        chunks.iter().map(|c| (c.start, c.end)).collect()
    }

    #[test]
    fn fixed_splitting_covers_the_input_exactly() {
        let data = vec![0u8; 10];
        let chunks = FixedSize::new(4).split(&data).expect("splits");
        assert_eq!(ranges(&chunks), vec![(0, 4), (4, 8), (8, 10)]);
        // Contiguity is the property the engine depends on.
        assert!(chunks.windows(2).all(|pair| pair[0].end == pair[1].start));
        assert_eq!(chunks.first().unwrap().start, 0);
        assert_eq!(chunks.last().unwrap().end, data.len());
    }

    #[test]
    fn an_empty_file_produces_no_chunks() {
        let chunks = FixedSize::new(4).split(b"").expect("splits");
        assert!(chunks.is_empty());
    }

    #[test]
    fn a_chunker_with_a_zero_size_still_terminates() {
        let chunks = FixedSize::new(0).split(b"abc").expect("splits");
        assert_eq!(ranges(&chunks), vec![(0, 1), (1, 2), (2, 3)]);
    }

    #[test]
    fn slices_come_back_the_right_size() {
        let data: Vec<u8> = (0..10).collect();
        let chunks = FixedSize::new(4).split(&data).expect("splits");
        assert_eq!(chunks[0].slice(&data), &[0, 1, 2, 3]);
        assert_eq!(chunks[2].slice(&data), &[8, 9]);
        assert_eq!(chunks[2].len(), 2);
    }

    #[test]
    fn slicing_clamps_to_the_buffer() {
        // A stale index can describe a range wider than the file we managed to
        // read, so slicing has to clamp instead of panicking.
        assert_eq!(Chunk::new(0, 100).slice(b"ab"), b"ab");
        assert!(Chunk::new(5, 9).slice(b"ab").is_empty());
    }

    #[test]
    fn fastcdc_covers_the_input_contiguously() {
        let data = pseudo_random(200_000);
        let chunks = FastCdc::new().split(&data).expect("splits");
        assert!(!chunks.is_empty());
        assert_eq!(chunks.first().unwrap().start, 0);
        assert_eq!(chunks.last().unwrap().end, data.len());
        assert!(chunks.windows(2).all(|pair| pair[0].end == pair[1].start));
        // Reassembly is the input, byte for byte.
        let rebuilt: Vec<u8> = chunks
            .iter()
            .flat_map(|c| c.slice(&data))
            .copied()
            .collect();
        assert_eq!(rebuilt, data);
    }

    #[test]
    fn fastcdc_respects_min_and_max_except_the_tail() {
        let data = pseudo_random(3_000_000);
        let cdc = FastCdc::new();
        let chunks = FastCdc::new().split(&data).expect("splits");
        let last = chunks.len() - 1;
        for (i, c) in chunks.iter().enumerate() {
            assert!(c.len() <= cdc.max, "chunk {i} exceeds max");
            // Every chunk but the final tail must reach the minimum.
            if i != last {
                assert!(c.len() >= cdc.min, "chunk {i} below min");
            }
        }
        // Normalized chunking aims near the target; check it is not wildly off.
        let avg = data.len() / chunks.len();
        assert!(avg > cdc.min && avg < cdc.max);
    }

    #[test]
    fn fastcdc_is_deterministic() {
        let data = pseudo_random(500_000);
        let a = FastCdc::new().split(&data).unwrap();
        let b = FastCdc::new().split(&data).unwrap();
        assert_eq!(a, b);
    }

    /// A reader that hands out at most `limit` bytes per call, so the streaming
    /// state machine is exercised at arrival granularities no fill size would
    /// naturally produce.
    struct SmallReads<'a, R: std::io::Read> {
        inner: &'a mut R,
        limit: usize,
    }

    impl<R: std::io::Read> std::io::Read for SmallReads<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.limit.min(buf.len());
            self.inner.read(&mut buf[..n])
        }
    }

    #[test]
    fn a_streamed_split_cuts_exactly_where_the_buffered_one_does() {
        // The format promise: chunk ids are content addresses, so the streaming
        // path may never cut a byte differently from the buffered one — not at a
        // minimum, not at a maximum, not at a tail, and not at any arrival
        // granularity. Any drift here corrupts vaults; nothing less passes.
        let sizes = [
            0usize,
            1,
            7,
            100,
            CHUNK_MIN - 1,
            CHUNK_MIN,
            CHUNK_MIN + 1,
            CHUNK_TARGET,
            CHUNK_TARGET + 1,
            CHUNK_MAX - 1,
            CHUNK_MAX,
            CHUNK_MAX + 1,
            CHUNK_MAX * 2,
            CHUNK_MAX * 3 + 12_345,
            1_500_000,
        ];
        for len in sizes {
            let data = pseudo_random(len);
            let expected: Vec<Vec<u8>> = FastCdc::new()
                .split(&data)
                .expect("splits")
                .iter()
                .map(|c| c.slice(&data).to_vec())
                .collect();

            for limit in [1usize, 64, 4096, STREAM_FILL * 3] {
                let mut got: Vec<Vec<u8>> = Vec::new();
                let mut cursor = std::io::Cursor::new(&data);
                let mut reader = SmallReads {
                    inner: &mut cursor,
                    limit,
                };
                let count = FastCdc::new()
                    .split_stream(&mut reader, |chunk| {
                        got.push(chunk.to_vec());
                        Ok(())
                    })
                    .unwrap_or_else(|e| panic!("len {len} limit {limit}: {e}"));
                assert_eq!(got, expected, "len {len} limit {limit}");
                assert_eq!(count, expected.len());
            }
        }
    }

    #[test]
    fn a_streamed_sink_failure_stops_the_split_right_there() {
        let data = pseudo_random(CHUNK_MAX * 2);
        let mut cursor = std::io::Cursor::new(&data);
        let mut seen = 0usize;
        let error = FastCdc::new()
            .split_stream(&mut cursor, |_| {
                seen += 1;
                Err(SyncError::Integrity("the sink said no"))
            })
            .expect_err("the sink's no is the splitter's no");
        assert!(matches!(error, SyncError::Integrity(_)));
        assert_eq!(seen, 1, "the splitter pressed on past a refused chunk");
    }

    #[test]
    fn an_edit_only_resplits_local_boundaries() {
        // The reason for content-defined chunking at all: inserting one byte near
        // the front of a large file should leave most chunks byte-identical, so
        // most chunk ids are unchanged and stay on the server. A fixed splitter
        // would change every chunk after the insertion.
        let before = pseudo_random(1_500_000);
        let mut after = before.clone();
        after.splice(1000..1000, [0x7Fu8; 64]); // insert 64 bytes near the front

        let ids_of = |buf: &[u8]| -> std::collections::HashSet<Vec<u8>> {
            FastCdc::new()
                .split(buf)
                .unwrap()
                .iter()
                .map(|c| c.slice(buf).to_vec())
                .collect()
        };
        let set_before = ids_of(&before);
        let set_after = ids_of(&after);

        // A large majority of the original chunks survive unchanged.
        let survived = set_before.iter().filter(|c| set_after.contains(*c)).count();
        assert!(
            survived * 2 > set_before.len(),
            "delta locality failed: only {survived}/{} chunks survived",
            set_before.len()
        );
    }

    #[test]
    fn a_broken_size_configuration_is_rejected_before_splitting() {
        let mut cdc = FastCdc {
            min: 1024,
            target: 512,
            max: 256,
        };
        let err = cdc.split(b"payload").expect_err("min must be under max");
        assert!(matches!(err, SyncError::ChunkTooLarge { .. }));
    }

    /// A deterministic pseudorandom buffer, so the split tests are reproducible.
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..len {
            // xorshift64*: cheap, deterministic, byte-like entropy.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            out.push((state.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8);
        }
        out
    }
}
