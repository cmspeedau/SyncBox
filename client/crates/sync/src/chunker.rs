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

/// The content-defined splitter Syncbox ships.
///
/// Boundaries come from a rolling hash over the input, clamped to
/// [`CHUNK_MIN`] and [`CHUNK_MAX`] and aiming at [`CHUNK_TARGET`], so pathological
/// input cannot produce a million tiny chunks or one enormous one.
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

    /// True when the configuration is usable: the minimum has to sit under the
    /// maximum, or the clamp could not produce anything valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.min > 0 && self.min < self.target && self.target < self.max
    }
}

impl Chunker for FastCdc {
    fn split(&mut self, data: &[u8]) -> Result<Vec<Chunk>> {
        let _ = data;
        if !self.is_valid() {
            return Err(SyncError::ChunkTooLarge {
                actual: self.max,
                limit: self.min,
            });
        }
        Err(SyncError::Unimplemented("FastCDC content-defined chunking"))
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
    fn the_default_splitter_is_valid_and_still_a_stub() {
        let cdc = FastCdc::new();
        assert!(cdc.is_valid());
        let err = FastCdc::new()
            .split(b"payload")
            .expect_err("M3 implements the splitter");
        assert!(matches!(err, SyncError::Unimplemented(_)));
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
}
