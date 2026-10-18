package api

// The three sync-space surfaces (M11 S3): browse, share and the recycle bin.
//
// They exist for one kind of space — the one registered as `sync`, whose names,
// paths and bytes the server may read. A vault answers `403` with a code, not
// prose, because the link the mode promises is not one the server can keep:
// browsing ciphertext would show nothing, and a share the server cannot read is
// not a share. The check is `requireSyncSpace`, and every handler below runs it
// before it touches a revision.

import (
	"context"
	"io"
	"log"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/syncbox/server/internal/store"
)

// requireSyncSpace resolves a space's mode and refuses a vault with the given
// code. It writes the refusal itself, so a handler that calls it and sees false
// returns immediately. A vault's refusal is a `403` and an unknown space is the
// `404` VaultMode already reports.
func (s *Server) requireSyncSpace(ctx context.Context, w http.ResponseWriter, vaultID, code, reason string) bool {
	mode, err := s.store.VaultMode(ctx, vaultID)
	if err != nil {
		writeErrorFrom(w, err)
		return false
	}
	if mode != store.ModeSync {
		writeError(w, http.StatusForbidden, code, reason)
		return false
	}
	return true
}

// fileView is one file as the browse, recycle and restore surfaces hand it back:
// the opaque key the client uses to address it, plus the cleartext path the
// server decoded for a human — which only a sync space has.
type fileView struct {
	DirID      string `json:"dir_id"`
	CipherName string `json:"cipher_name"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	ModifiedAt int64  `json:"modified_unix"`
	Revision   uint64 `json:"revision"`
}

// newFileView renders one file, decoding its directory id into a path. A vault
// never reaches here; a sync space's ids always decode, and one that does not
// is still shown, addressed by its raw id and named by its file name alone,
// because hiding it would be worse than showing it plainly.
func newFileView(file store.File) fileView {
	relDir, ok := syncDirPath(file.DirID)
	if !ok {
		relDir = ""
	}
	return fileView{
		DirID:      file.DirID,
		CipherName: file.CipherName,
		Path:       syncPath(relDir, file.CipherName),
		Size:       file.Size,
		ModifiedAt: file.ModifiedAt,
		Revision:   file.Revision,
	}
}

// handleFilesList is the browse read: the space's live files, each with the
// cleartext path the server decoded from its directory id. It is a query over
// the same tally the registry already computes — newest revision per
// (dir_id, cipher_name), deleted excluded — not a second index.
func (s *Server) handleFilesList(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if !s.requireSyncSpace(r.Context(), w, vaultID, "not_browsable",
		"this space is a vault: the server holds only ciphertext, so it has no files to list") {
		return
	}

	files, err := s.store.LiveFiles(r.Context(), vaultID)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	out := make([]fileView, 0, len(files))
	for _, file := range files {
		out = append(out, newFileView(file))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_id": vaultID,
		"files":    out,
	})
}

// recycleView is one bin entry: the same key and path a file view carries, plus
// when the deletion landed.
type recycleView struct {
	DirID      string `json:"dir_id"`
	CipherName string `json:"cipher_name"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	DeletedAt  int64  `json:"deleted_unix"`
	Revision   uint64 `json:"revision"`
}

// handleRecycleList is the recycle bin: the space's tombstones, most recently
// deleted first, limited to those the retention window has not yet expired.
// With retention disabled every tombstone is shown.
func (s *Server) handleRecycleList(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if !s.requireSyncSpace(r.Context(), w, vaultID, "not_recyclable",
		"this space is a vault: the server cannot read a deletion, so it has no recycle bin") {
		return
	}

	since := int64(0)
	if s.recycleDays > 0 {
		since = s.now().Add(-time.Duration(s.recycleDays) * 24 * time.Hour).Unix()
	}
	entries, err := s.store.RecycleBin(r.Context(), vaultID, since)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	out := make([]recycleView, 0, len(entries))
	for _, entry := range entries {
		relDir, ok := syncDirPath(entry.DirID)
		if !ok {
			relDir = ""
		}
		out = append(out, recycleView{
			DirID:      entry.DirID,
			CipherName: entry.CipherName,
			Path:       syncPath(relDir, entry.CipherName),
			Size:       entry.Size,
			DeletedAt:  entry.DeletedAt,
			Revision:   entry.Revision,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vault_id":       vaultID,
		"deleted":        out,
		"retention_days": s.recycleDays,
	})
}

// recycleRestoreBody names the file to bring back from the bin.
type recycleRestoreBody struct {
	DirID      string `json:"dir_id"`
	CipherName string `json:"cipher_name"`
}

// handleRecycleRestore takes one file out of the bin by committing a fresh copy
// of its last live revision against the current head, so every client pulls it
// back on its next pass. It is the one surface where the server writes into the
// log, and it does so as an ordinary commit: nothing about the protocol changes.
func (s *Server) handleRecycleRestore(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if !s.requireSyncSpace(r.Context(), w, vaultID, "not_recyclable",
		"this space is a vault: the server cannot read a deletion, so it has no recycle bin") {
		return
	}

	var request recycleRestoreBody
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"restoring a file needs a JSON body with dir_id and cipher_name")
		return
	}
	if strings.TrimSpace(request.CipherName) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "cipher_name must name a file")
		return
	}

	file, err := s.store.RestoreRecycled(r.Context(), vaultID, request.DirID, request.CipherName)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	// The restore is a commit; wake anyone long-polling this space so they
	// re-read, exactly as handleCommit does.
	s.hub.publish(vaultID)
	writeJSON(w, http.StatusCreated, newFileView(file))
}

// shareCreateBody names the file a link is minted for and, optionally, a shorter
// life than the server's maximum.
type shareCreateBody struct {
	DirID            string `json:"dir_id"`
	CipherName       string `json:"cipher_name"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

// shareView is what a mint answers: the link, and enough of the file for the
// console to show what it points at without a second read.
type shareView struct {
	Token            string `json:"token"`
	URL              string `json:"url"`
	VaultID          string `json:"vault_id"`
	DirID            string `json:"dir_id"`
	CipherName       string `json:"cipher_name"`
	Path             string `json:"path"`
	ExpiresUnix      int64  `json:"expires_unix"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

// handleShareCreate mints a signed, expiring link to one file in a sync space.
// The link carries only the file it names and when it dies; a request may ask
// for a shorter life than the server's ceiling but never a longer one.
func (s *Server) handleShareCreate(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if !s.requireSyncSpace(r.Context(), w, vaultID, "not_shareable",
		"this space is a vault: a share link the server cannot read is not a share") {
		return
	}

	var request shareCreateBody
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"sharing a file needs a JSON body with dir_id and cipher_name")
		return
	}
	if strings.TrimSpace(request.CipherName) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "cipher_name must name a file")
		return
	}
	// Only a file the space actually holds is shareable, and the read is what
	// proves it: a link to nothing would resolve to a 404 later.
	rev, err := s.store.LiveFile(r.Context(), vaultID, request.DirID, request.CipherName)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	// And the file has to be readable *as a file*: its manifest is what the
	// download follows to find the chunks, so a record that does not parse —
	// a revision committed by an older or stranger client — is refused here
	// rather than as a failure on whoever ends up holding the link.
	if _, err := parseSyncManifest(rev.Manifest); err != nil {
		writeError(w, http.StatusBadRequest, "unreadable_manifest",
			"this file's record is not a sync-space manifest, so the server cannot serve it")
		return
	}

	ttl := s.shareTTL
	if request.ExpiresInSeconds > 0 {
		if requested := time.Duration(request.ExpiresInSeconds) * time.Second; requested < ttl {
			ttl = requested
		}
	}
	now := s.now()
	token, err := s.issuer.IssueShare(vaultID, request.DirID, request.CipherName, ttl, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "share_failed", err.Error())
		return
	}

	relDir, ok := syncDirPath(request.DirID)
	if !ok {
		relDir = ""
	}
	writeJSON(w, http.StatusCreated, shareView{
		Token:            token,
		URL:              "/api/v1/shares/" + token,
		VaultID:          vaultID,
		DirID:            request.DirID,
		CipherName:       request.CipherName,
		Path:             syncPath(relDir, request.CipherName),
		ExpiresUnix:      now.Add(ttl).Unix(),
		ExpiresInSeconds: int64(ttl.Seconds()),
	})
}

// handleShareGet serves a shared file to whoever holds the link. There is no
// bearer token: the link is the credential, and it names one file until it
// expires. The bytes stream chunk by chunk, so a shared video costs a chunk of
// memory, not a copy of the file.
//
// The reply is always an attachment with a nosniff hint: a share is the one
// place the server hands out content it did not author, and a shared HTML file
// must download rather than run on the server's own origin, where the console's
// session lives.
func (s *Server) handleShareGet(w http.ResponseWriter, r *http.Request) {
	claims, err := s.issuer.VerifyShare(r.PathValue("token"), s.now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "this share link is not valid or has expired")
		return
	}

	// The link is only readable while the space is still one the server reads.
	mode, err := s.store.VaultMode(r.Context(), claims.VaultID)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	if mode != store.ModeSync {
		writeError(w, http.StatusNotFound, "not_found", "the space this link names is no longer readable")
		return
	}
	rev, err := s.store.LiveFile(r.Context(), claims.VaultID, claims.DirID, claims.CipherName)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	manifest, err := parseSyncManifest(rev.Manifest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "unreadable_manifest", err.Error())
		return
	}

	head := w.Header()
	head.Set("Content-Type", contentTypeFor(claims.CipherName))
	head.Set("Content-Length", strconv.FormatInt(manifest.storedBytes(), 10))
	head.Set("X-Content-Type-Options", "nosniff")
	if disposition := mime.FormatMediaType("attachment", map[string]string{"filename": claims.CipherName}); disposition != "" {
		head.Set("Content-Disposition", disposition)
	}

	for _, chunk := range manifest.Chunks {
		reader, err := s.store.OpenChunk(r.Context(), chunk.ID)
		if err != nil {
			// Headers are already on the wire; the truncated body is what the
			// client notices, and there is nothing left to shape.
			log.Printf("api: serving share chunk %s: %v", chunk.ID, err)
			return
		}
		_, copyErr := io.Copy(w, reader)
		reader.Close()
		if copyErr != nil {
			log.Printf("api: streaming share chunk %s: %v", chunk.ID, copyErr)
			return
		}
	}
}

// contentTypeFor guesses a shared file's type from its name, falling back to a
// download when the extension says nothing.
func contentTypeFor(name string) string {
	if kind := mime.TypeByExtension(filepath.Ext(name)); kind != "" {
		return kind
	}
	return "application/octet-stream"
}
