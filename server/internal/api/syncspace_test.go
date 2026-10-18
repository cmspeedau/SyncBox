package api

import (
	"strings"
	"testing"
)

// The server only ever decodes a sync space's naming, so these tests need an
// encoder to decode against: the client's is the spec, and this is the same
// algorithm written from it (Crockford base32, no padding, leftover bits shifted
// into a final symbol).
func crockfordEncode(raw []byte) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var out strings.Builder
	var acc uint32
	var held uint32

	for _, b := range raw {
		acc = (acc << 8) | uint32(b)
		held += 8
		for held >= 5 {
			held -= 5
			out.WriteByte(alphabet[(acc>>held)&0x1F])
			acc &= (uint32(1) << held) - 1
		}
	}
	if held > 0 {
		out.WriteByte(alphabet[(acc<<(5-held))&0x1F])
	}
	return out.String()
}

// syncDirID is what a sync client writes into dir_id for a relative directory:
// its path tagged with a leading NUL, base32-encoded.
func syncDirID(rel string) string {
	return crockfordEncode(append([]byte{0}, rel...))
}

func TestSyncDirPathRoundTripsTheClientsEncoding(t *testing.T) {
	for _, rel := range []string{"", "docs", "docs/2026", "a b/c-d", "Ünïcode", "deep/inner/most"} {
		id := syncDirID(rel)
		got, ok := syncDirPath(id)
		if !ok || got != rel {
			t.Errorf("syncDirPath(%q) = %q, %v; want %q", id, got, ok, rel)
		}
	}
	// A lowercase id still reads, as the client's decoder also allows.
	if got, ok := syncDirPath(strings.ToLower(syncDirID("docs"))); !ok || got != "docs" {
		t.Errorf("a lowercase id read as %q, %v; want docs", got, ok)
	}
}

func TestSyncDirPathRefusesWhatTheCodecCouldNotWrite(t *testing.T) {
	cases := map[string]string{
		"a vault's directory id":   crockfordEncode([]byte{7, 7, 7, 7, 7, 7, 7, 7}),
		"path traversal":           crockfordEncode(append([]byte{0}, []byte("../etc")...)),
		"an empty segment":         crockfordEncode(append([]byte{0}, []byte("a//b")...)),
		"a dot segment":            crockfordEncode(append([]byte{0}, []byte("a/./b")...)),
		"a backslash":              crockfordEncode(append([]byte{0}, []byte(`a\b`)...)),
		"not base32 at all":        "!!!",
		"a bare symbol with bytes": "A", // five bits, no whole byte behind it
		"the empty string":         "",
	}
	for name, id := range cases {
		if got, ok := syncDirPath(id); ok {
			t.Errorf("%s: syncDirPath(%q) decoded to %q, want refused", name, id, got)
		}
	}
}

func TestSyncPathJoinsWithoutDoublingSeparators(t *testing.T) {
	if got := syncPath("", "notes.txt"); got != "notes.txt" {
		t.Errorf("root path = %q, want notes.txt", got)
	}
	if got := syncPath("docs/2026", "notes.txt"); got != "docs/2026/notes.txt" {
		t.Errorf("nested path = %q, want docs/2026/notes.txt", got)
	}
}

func TestParseSyncManifestRoundTripsAndRejects(t *testing.T) {
	body := "hello in the clear"
	manifest := buildSyncManifest(t, uint64(len(body)), chunkOf(body))

	parsed, err := parseSyncManifest(decodeManifestBytes(t, manifest))
	if err != nil {
		t.Fatalf("parseSyncManifest: %v", err)
	}
	if parsed.Size != uint64(len(body)) {
		t.Errorf("size = %d, want %d", parsed.Size, len(body))
	}
	if len(parsed.Chunks) != 1 || parsed.Chunks[0].StoredLen != uint32(len(body)) {
		t.Fatalf("chunks = %+v, want one chunk of %d bytes", parsed.Chunks, len(body))
	}
	if parsed.storedBytes() != int64(len(body)) {
		t.Errorf("storedBytes = %d, want %d", parsed.storedBytes(), len(body))
	}

	raw := decodeManifestBytes(t, manifest)
	for name, broken := range map[string][]byte{
		"too short":     raw[:8],
		"the wrong tag": append([]byte("SBXVAULT"), raw[8:]...),
		"truncated":     raw[:len(raw)-1],
		"trailing":      append(append([]byte(nil), raw...), 0),
		"empty":         {},
	} {
		if _, err := parseSyncManifest(broken); err == nil {
			t.Errorf("%s: parsed a broken manifest, want an error", name)
		}
	}
}

// TestParseSyncManifestIgnoresAnInflatedCount is the memory-safety half: a
// hostile count must not allocate before the bytes vouch for it, and must not
// make the reader walk past the record.
func TestParseSyncManifestIgnoresAnInflatedCount(t *testing.T) {
	var raw []byte
	raw = append(raw, []byte(syncManifestMagic)...)
	raw = append(raw, 0, 0, 0, 0, 0, 0, 0, 0) // size 0
	raw = append(raw, 0xFF, 0xFF, 0xFF, 0xFF) // count 4294967295, no chunks behind it
	if _, err := parseSyncManifest(raw); err == nil {
		t.Error("an inflated chunk count parsed clean, want an error")
	}
}
