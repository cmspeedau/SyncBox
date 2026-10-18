package api

// The sync-space codec (M11 S3): how the server reads what a sync-mode client
// wrote.
//
// A sync space stores a directory's relative path base32-encoded in `dir_id`
// and the file's name in the clear in `cipher_name`, and a manifest is a small
// cleartext record rather than an encrypted envelope. This file is the server's
// half of `client/crates/sync/src/plain.rs`, and the only place a handler parses
// client bytes — which is the point of the mode: a vault's rows are ciphertext
// the server never interprets, a sync space's are cleartext it reads, indexes
// and serves. Every handler that reaches here has checked the mode first.
//
// The encoding is deliberate, not incidental, and lives in docs/protocol.md: a
// directory id is `CROCKFORD_BASE32(0x00 || relative_path)`, the leading NUL
// keeping the root non-empty and the mapping unambiguous (no filesystem path may
// hold a NUL). A manifest is `SBXSYNC1 || size:u64 || count:u32 || (stored_len:u32
// || id_len:u16 || id)*`, all little-endian, chunk ids being the plaintext
// chunk's SHA-256 in the same base32.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// crockford is Cryptomator's base32 alphabet, the one the client uses: it omits
// I, L, O and U so transcribed ids stay unambiguous.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// decodeBase32 decodes Crockford base32, accepting padding and either case and
// reading I/L as 1 and U as V, exactly as syncbox-crypto's decoder does. A
// trailing symbol that carries no whole byte is refused: this codec only ever
// decodes what its encoder wrote, and that never leaves five bits over.
func decodeBase32(text string) ([]byte, error) {
	var out []byte
	var acc uint32
	var held uint

	for _, ch := range text {
		if ch == '=' || ch == '-' {
			continue
		}
		value, ok := base32Symbol(ch)
		if !ok {
			return nil, fmt.Errorf("%q is not a base32 symbol", ch)
		}
		acc = (acc << 5) | uint32(value)
		held += 5
		if held >= 8 {
			held -= 8
			out = append(out, byte((acc>>held)&0xFF))
			acc &= (uint32(1) << held) - 1
		}
	}
	if held >= 5 {
		return nil, errors.New("trailing base32 symbol carries no whole byte")
	}
	return out, nil
}

// base32Symbol maps one Crockford symbol to its five-bit value, tolerating the
// handwriting spellings the client tolerates.
func base32Symbol(ch rune) (byte, bool) {
	switch {
	case ch >= 'a' && ch <= 'z':
		ch -= 'a' - 'A'
	}
	switch ch {
	case 'I', 'L':
		ch = '1'
	case 'U':
		ch = 'V'
	}
	index := strings.IndexRune(crockford, ch)
	if index < 0 {
		return 0, false
	}
	return byte(index), true
}

// syncDirPath decodes a sync space's `dir_id` into its relative directory path:
// the NUL tag byte, then the UTF-8 path. It returns false for an id this codec
// could not have written — a vault's HMAC, or anything holding traversal — so a
// caller shows the raw id rather than a path it invented.
func syncDirPath(dirID string) (string, bool) {
	raw, err := decodeBase32(dirID)
	if err != nil || len(raw) == 0 || raw[0] != 0 {
		return "", false
	}
	rel := string(raw[1:])
	if !safeSyncDir(rel) {
		return "", false
	}
	return rel, true
}

// safeSyncDir mirrors the client's rule: empty (the root), or `/`-separated
// segments with no empty, "." or ".." component and no backslash or NUL.
func safeSyncDir(rel string) bool {
	if strings.ContainsAny(rel, "\\\x00") {
		return false
	}
	if rel == "" {
		return true
	}
	for _, segment := range strings.Split(rel, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// syncPath joins a decoded directory and a file name with `/`, the index's
// separator.
func syncPath(relDir, name string) string {
	if relDir == "" {
		return name
	}
	return relDir + "/" + name
}

// syncManifestMagic tags the cleartext shape and tells it from a vault blob.
const syncManifestMagic = "SBXSYNC1"

// syncManifest is a decoded sync-space manifest: the file's plaintext size and
// its chunks in order.
type syncManifest struct {
	Size   uint64
	Chunks []syncChunk
}

// syncChunk is one entry: the chunk's content address and the bytes it stores.
type syncChunk struct {
	ID        string
	StoredLen uint32
}

// parseSyncManifest decodes a sync-space manifest, refusing a truncated or
// trailing-garbage record rather than trusting its count. It makes the same
// checks the client's decoder makes, and it allocates only from bytes the
// record has already vouched for.
func parseSyncManifest(data []byte) (syncManifest, error) {
	if len(data) < 20 || string(data[:8]) != syncManifestMagic {
		return syncManifest{}, errors.New("manifest is not a sync-space manifest")
	}
	manifest := syncManifest{Size: binary.LittleEndian.Uint64(data[8:16])}
	count := binary.LittleEndian.Uint32(data[16:20])

	rest := data[20:]
	for i := uint32(0); i < count; i++ {
		if len(rest) < 6 {
			return syncManifest{}, errors.New("manifest chunk is truncated")
		}
		storedLen := binary.LittleEndian.Uint32(rest[:4])
		idLen := int(binary.LittleEndian.Uint16(rest[4:6]))
		rest = rest[6:]
		if idLen == 0 || len(rest) < idLen {
			return syncManifest{}, errors.New("manifest chunk id is truncated")
		}
		manifest.Chunks = append(manifest.Chunks, syncChunk{
			ID:        string(rest[:idLen]),
			StoredLen: storedLen,
		})
		rest = rest[idLen:]
	}
	if len(rest) != 0 {
		return syncManifest{}, errors.New("manifest has trailing bytes after its chunks")
	}
	return manifest, nil
}

// storedBytes is how many bytes a manifest's chunks hold, which is what a
// share download will write: taken from the record rather than the revision's
// reported size, so a link is never given a Content-Length its body cannot meet.
func (m syncManifest) storedBytes() int64 {
	var total int64
	for _, chunk := range m.Chunks {
		total += int64(chunk.StoredLen)
	}
	return total
}
