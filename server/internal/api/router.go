// Package api is the HTTP surface the clients speak to.
//
// Two rules govern every handler here:
//
//   - Nothing decrypts. A handler may store, compare, and return an opaque blob;
//     it may not interpret one. That is what keeps the zero-knowledge claim true
//     even with a cooperative operator.
//   - Errors are shaped for a machine. Every non-2xx reply carries a code the
//     client branches on and a message meant for a log, which is how the sync
//     engine can tell "commit lost the race, make a conflicted copy" apart from
//     "token expired, ask for the password".
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/syncbox/server/internal/auth"
	"github.com/syncbox/server/internal/backup"
	"github.com/syncbox/server/internal/ratelimit"
	"github.com/syncbox/server/internal/store"
)

// Limits that bound what a single request can make the server hold in memory.
const (
	// MaxChunkBytes bounds one chunk upload.
	MaxChunkBytes = 8 << 20
	// MaxBodyBytes bounds a JSON request body.
	MaxBodyBytes = 1 << 20
	// DefaultRevisionPage is the page size when the client does not ask.
	DefaultRevisionPage = 500
	// DefaultEventWait is how long a client waits for a change before the events
	// long-poll returns empty, and MaxEventWait caps it below a typical proxy's
	// idle timeout so a held connection is ended by us, not dropped by the proxy.
	DefaultEventWait = 30 * time.Second
	MaxEventWait     = 60 * time.Second
)

// Server bundles what the handlers need.
type Server struct {
	store    store.Store
	backups  *backup.Manager
	issuer   *auth.Issuer
	password string
	version  string
	hub      *hub
	limiter  *ratelimit.Limiter // nil, or a zero-rate limiter, means unlimited
	now      func() time.Time
	// requireRegisteredVaults makes a commit to a vault the registry does not
	// know a refusal rather than a nameless birth. Off unless a deployment
	// turns it on, after its clients have moved to registered vaults.
	requireRegisteredVaults bool
}

// New returns a server over a store. backups may be nil, in which case the
// administrative endpoints report that backups are not configured.
func New(st store.Store, backups *backup.Manager, issuer *auth.Issuer, password string) *Server {
	return &Server{
		store:    st,
		backups:  backups,
		issuer:   issuer,
		password: password,
		hub:      newHub(),
		now:      time.Now,
	}
}

// SetRateLimit caps each caller's IP at rate requests per second with the given
// burst. It exists as a setter because the limiter is a deployment posture, not
// part of what a server is built over — a zero rate disables it, which is also
// the default, so a single-user server on loopback runs unthrottled.
func (s *Server) SetRateLimit(rate float64, burst int) {
	s.limiter = ratelimit.New(rate, burst)
}

// SetVersion tells the server its own release string, so the root name-card
// can answer "what is this" with more than a guess. It is a setter for the
// same reason the limiter is: the stamp belongs to the build, not to what a
// server is built over.
func (s *Server) SetVersion(version string) {
	s.version = version
}

// SetRequireRegisteredVaults turns the registry into a gate: with it on, a
// commit to a vault id the registry does not know is refused, instead of
// birthing a vault nameless. It is a setter for the same reason the limiter
// is — a deployment posture, chosen per host and turned on only after every
// client has been pointed at a registered vault, so turning it on breaks no
// client still in flight.
func (s *Server) SetRequireRegisteredVaults(require bool) {
	s.requireRegisteredVaults = require
}

// Routes builds the handler tree.
//
// Health is the only route that needs no token: a reverse proxy and a container
// orchestrator both probe before anything has logged in.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /api/v1/auth/token", s.handleToken)

	// The root answers instead of 404-ing: the embedded console for browsers,
	// a JSON name-card for scripts (see handleIndex). {$} pins it to exactly
	// "/": a bare "/" pattern is the mux's catch-all and would hand the card
	// — or a 405 — to every unmatched path on the server.
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /app.js", s.handleAsset("app.js"))
	mux.HandleFunc("GET /style.css", s.handleAsset("style.css"))

	// Everything below the vault prefix is authenticated.
	mux.Handle("GET /api/v1/vaults/{vaultID}/revisions", s.requireToken(http.HandlerFunc(s.handleListRevisions)))
	mux.Handle("POST /api/v1/vaults/{vaultID}/revisions", s.requireToken(http.HandlerFunc(s.handleCommit)))
	mux.Handle("GET /api/v1/vaults/{vaultID}/events", s.requireToken(http.HandlerFunc(s.handleEvents)))

	mux.Handle("POST /api/v1/vaults/{vaultID}/chunks/exists", s.requireToken(http.HandlerFunc(s.handleChunksExist)))
	mux.Handle("HEAD /api/v1/vaults/{vaultID}/chunks/{chunkID}", s.requireToken(http.HandlerFunc(s.handleChunkHead)))
	mux.Handle("GET /api/v1/vaults/{vaultID}/chunks/{chunkID}", s.requireToken(http.HandlerFunc(s.handleChunkGet)))
	mux.Handle("PUT /api/v1/vaults/{vaultID}/chunks/{chunkID}", s.requireToken(http.HandlerFunc(s.handleChunkPut)))

	mux.Handle("GET /admin/backups", s.requireToken(http.HandlerFunc(s.handleBackupsList)))
	mux.Handle("POST /admin/backups", s.requireToken(http.HandlerFunc(s.handleBackupCreate)))
	mux.Handle("POST /admin/backups/{id}/verify", s.requireToken(http.HandlerFunc(s.handleBackupVerify)))
	mux.Handle("POST /admin/backups/{id}/restore", s.requireToken(http.HandlerFunc(s.handleBackupRestore)))

	mux.Handle("GET /vaults", s.requireToken(http.HandlerFunc(s.handleVaultsListClient)))

	mux.Handle("GET /admin/vaults", s.requireToken(http.HandlerFunc(s.handleAdminVaultsList)))
	mux.Handle("POST /admin/vaults", s.requireToken(http.HandlerFunc(s.handleAdminVaultsCreate)))
	mux.Handle("PATCH /admin/vaults/{id}", s.requireToken(http.HandlerFunc(s.handleAdminVaultsPatch)))
	mux.Handle("POST /admin/vaults/{id}/archive", s.requireToken(http.HandlerFunc(s.handleAdminVaultsArchive)))

	var handler http.Handler = mux
	handler = s.limit(handler)
	handler = recoverMiddleware(handler)
	handler = logMiddleware(handler)
	return handler
}

// limit guards every route — probes, login included — by caller IP, before a
// request buys any HMAC work, any Argon2, or any chunk I/O. Refusals answer the
// protocol's stable `rate_limited` code with a Retry-After, which the client's
// chunk transfers retry against with doubling backoff.
func (s *Server) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, wait := s.limiter.Allow(ipKey(r.RemoteAddr)); !ok {
			seconds := int64(math.Ceil(wait.Seconds()))
			if seconds < 1 {
				seconds = 1
			}
			w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				"too many requests for this address; retry after "+strconv.FormatInt(seconds, 10)+"s")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ipKey strips the port off RemoteAddr, so one address holds one bucket no
// matter how many connections it opens.
func ipKey(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// healthBody is what /healthz answers.
type healthBody struct {
	Status  string      `json:"status"`
	Time    time.Time   `json:"time"`
	Storage store.Stats `json:"storage"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	stats, err := s.store.Stats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_unavailable", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, healthBody{Status: "ok", Time: s.now().UTC(), Storage: stats})
}

// tokenRequest is the body of POST /api/v1/auth/token.
type tokenRequest struct {
	Password string `json:"password"`
}

// tokenResponse is what a successful token exchange returns.
type tokenResponse struct {
	Token       string `json:"token"`
	ExpiresUnix int64  `json:"expires_unix"`
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	var request tokenRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	// Single-user v1: there is one password, and a correct one buys a token for
	// "owner". Comparison is not constant-time against the configured value, but
	// the value is a long random secret rather than a human guess, and the TLS
	// layer is what an attacker actually faces.
	if s.password == "" || request.Password != s.password {
		writeError(w, http.StatusUnauthorized, "unauthorized", "password mismatch")
		return
	}

	token, err := s.issuer.Issue("owner", s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		Token:       token,
		ExpiresUnix: s.now().Add(s.issuer.TTL()).Unix(),
	})
}

// revisionPage is the body of GET .../revisions.
type revisionPage struct {
	Revisions []store.Revision `json:"revisions"`
	Upto      uint64           `json:"upto"`
}

// handleListRevisions answers a plain revisions GET.
func (s *Server) handleListRevisions(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	since, err := parseUint(r.URL.Query().Get("since"), 0)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	limit, err := parseUint(r.URL.Query().Get("limit"), DefaultRevisionPage)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	page, err := s.readRevisions(r.Context(), vaultID, since, int(limit))
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// commitRequest is the body of POST .../revisions.
type commitRequest struct {
	Parent   uint64         `json:"parent"`
	Revision store.Revision `json:"revision"`
}

func (s *Server) handleCommit(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")

	// Enforcement (S5): with the toggle on, the registry is the only way a
	// vault comes to exist. Refusing here — before the body is even read —
	// keeps a mistyped or retired vault id from quietly birthing a namespace,
	// while the default (off) leaves every pre-registry client working.
	if s.requireRegisteredVaults {
		registered, err := s.store.VaultRegistered(r.Context(), vaultID)
		if err != nil {
			writeErrorFrom(w, err)
			return
		}
		if !registered {
			writeError(w, http.StatusForbidden, "unknown_vault",
				"this server accepts commits only to vaults in its registry; create the vault in the console first")
			return
		}
	}

	var request commitRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	// The client names the revision it branched from; the path is the vault's
	// identity, so the two must agree or a client could write into another vault.
	request.Revision.VaultID = vaultID
	if request.Parent != request.Revision.Parent {
		writeError(w, http.StatusBadRequest, "bad_request", "parent and revision.parent disagree")
		return
	}

	next, err := s.store.Commit(r.Context(), request.Revision)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	// The revision is durable; wake anyone long-polling this vault so they re-read.
	s.hub.publish(vaultID)
	writeJSON(w, http.StatusCreated, map[string]uint64{"revision": next})
}

// chunkCheckRequest is the body of POST .../chunks/exists.
type chunkCheckRequest struct {
	IDs []string `json:"ids"`
}

// chunkCheckResponse names the chunks the server does not hold.
type chunkCheckResponse struct {
	Missing []string `json:"missing"`
}

func (s *Server) handleChunksExist(w http.ResponseWriter, r *http.Request) {
	var request chunkCheckRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	for _, id := range request.IDs {
		if err := store.CheckChunkID(id); err != nil {
			writeError(w, http.StatusBadRequest, "bad_chunk_id", err.Error())
			return
		}
	}

	missing, err := s.store.MissingChunks(r.Context(), request.IDs)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, chunkCheckResponse{Missing: missing})
}

func (s *Server) handleChunkHead(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("chunkID")
	size, err := s.store.ChunkSize(r.Context(), id)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleChunkGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("chunkID")
	reader, err := s.store.OpenChunk(r.Context(), id)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := io.Copy(w, reader); err != nil {
		// Headers are already on the wire, so this can only be logged.
		log.Printf("api: streaming chunk %s: %v", id, err)
	}
}

func (s *Server) handleChunkPut(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("chunkID")
	if err := store.CheckChunkID(id); err != nil {
		writeError(w, http.StatusBadRequest, "bad_chunk_id", err.Error())
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxChunkBytes)
	written, err := s.store.PutChunk(r.Context(), id, r.Body)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"stored": written})
}

func (s *Server) handleBackupsList(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "not_configured", "no backup target is configured")
		return
	}
	snapshots, err := s.backups.List(r.Context())
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, snapshots)
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "not_configured", "no backup target is configured")
		return
	}
	snapshot, err := s.backups.Create(r.Context(), backup.DefaultPolicy())
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, snapshot)
}

// verifyBody is the reply to verifying a snapshot: what was just proven, in
// enough numbers for an operator to recognise the snapshot they asked about.
type verifyBody struct {
	ID             string `json:"id"`
	Chunks         int    `json:"chunks"`
	ChunkBytes     int64  `json:"chunk_bytes"`
	MetadataSHA256 string `json:"metadata_sha256"`
}

func (s *Server) handleBackupVerify(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "not_configured", "no backup target is configured")
		return
	}
	manifest, err := s.backups.Verify(r.Context(), r.PathValue("id"))
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyBody{
		ID:             manifest.ID,
		Chunks:         len(manifest.Chunks),
		ChunkBytes:     manifest.ChunkBytes,
		MetadataSHA256: manifest.MetadataSHA256,
	})
}

// restoreBody asks for a snapshot's contents to be copied into an empty (or
// absent) directory the server can write — the offline restore drill.
type restoreBody struct {
	DestDir string `json:"dest_dir"`
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	if s.backups == nil {
		writeError(w, http.StatusNotImplemented, "not_configured", "no backup target is configured")
		return
	}
	var request restoreBody
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "restore needs a JSON body with dest_dir")
		return
	}
	if strings.TrimSpace(request.DestDir) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "dest_dir must name a directory")
		return
	}
	manifest, err := s.backups.Restore(r.Context(), r.PathValue("id"), request.DestDir)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          manifest.ID,
		"dest_dir":    request.DestDir,
		"chunks":      len(manifest.Chunks),
		"chunk_bytes": manifest.ChunkBytes,
	})
}

// requireToken rejects a request whose bearer token this server did not sign.
func (s *Server) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token, found := strings.CutPrefix(header, "Bearer ")
		if !found || token == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		if _, err := s.issuer.Verify(token, s.now()); err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "token rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// errorBody is the body of every non-2xx reply.
type errorBody struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

func writeError(w http.ResponseWriter, status int, code, reason string) {
	writeJSON(w, status, errorBody{Code: code, Reason: reason})
}

// writeErrorFrom maps a store or backup error onto a status and code.
//
// The mapping is the API's contract with the client, so the sentinel errors are
// matched with errors.Is rather than compared by hand.
func writeErrorFrom(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, store.ErrLocationTaken):
		writeError(w, http.StatusConflict, "location_taken", err.Error())
	case errors.Is(err, store.ErrBadMode):
		writeError(w, http.StatusBadRequest, "invalid_mode", err.Error())
	case errors.Is(err, store.ErrTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", err.Error())
	case errors.Is(err, store.ErrBadChunkID):
		writeError(w, http.StatusBadRequest, "bad_chunk_id", err.Error())
	case errors.Is(err, auth.ErrInvalidToken):
		writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
	case errors.Is(err, backup.ErrIncomplete):
		writeError(w, http.StatusNotFound, "incomplete_snapshot", err.Error())
	case errors.Is(err, backup.ErrCorrupt):
		writeError(w, http.StatusInternalServerError, "corrupt_snapshot", err.Error())
	case errors.Is(err, backup.ErrRefusesOverwrite):
		writeError(w, http.StatusConflict, "restore_target_occupied", err.Error())
	case errors.Is(err, os.ErrNotExist):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(body); err != nil {
		fmt.Printf("api: writing response: %v\n", err)
	}
}

// decodeJSON reads a bounded request body into dst.
func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("request has no body")
	}
	defer r.Body.Close()

	// The ceiling is enforced by the reader, so an oversized body surfaces as a
	// MaxBytesError that can be named rather than as truncated JSON.
	r.Body = http.MaxBytesReader(nil, r.Body, MaxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		var exceeded *http.MaxBytesError
		if errors.As(err, &exceeded) {
			return fmt.Errorf("body exceeds %d bytes", MaxBodyBytes)
		}
		return fmt.Errorf("decoding request body: %w", err)
	}
	return nil
}

// parseUint reads an optional numeric query parameter.
func parseUint(raw string, fallback uint64) (uint64, error) {
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("query value %q is not a number", raw)
	}
	return value, nil
}

// logMiddleware prints one line per request, so a running container is debuggable
// without a logging stack.
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)
		log.Printf("api: %s %s -> %d in %s", r.Method, r.URL.Path, recorder.status, time.Since(start))
	})
}

// statusRecorder remembers the status a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// recoverMiddleware turns a panic in one request into a 500 instead of taking the
// process down with every other client on it.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("api: panic handling %s %s: %v", r.Method, r.URL.Path, recovered)
				writeError(w, http.StatusInternalServerError, "internal", "recovered from a panic")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
