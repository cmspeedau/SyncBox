package api

// The first-run surfaces: how a fresh server says "I have no password yet" and how
// it is given one. They are the only two routes a server answers before a
// credential exists, and they exist so an operator can bootstrap a deployment from
// the console instead of reading a generated secret out of a log line. After a
// first run both report the door closed and the ordinary /auth/token takes over.

import (
	"net/http"

	"github.com/syncbox/server/internal/credential"
)

// authStatusBody is what GET /api/v1/auth/status answers. The console reads it on
// the login screen to choose between "sign in" and "set the server password".
type authStatusBody struct {
	Initialized bool `json:"initialized"`
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, authStatusBody{Initialized: s.creds.Initialized()})
}

// handleAuthSetup stores the first password. It is good once: while the server is
// uninitialized any caller may set the password (that is the whole point, and it
// is why a deployment reaching for a network before finishing setup should set
// SYNCBOX_PASSWORD instead); the moment one exists, every later call is refused.
// The credential is sealed with Argon2id by the authority, never stored in the
// clear, and the write is durable before the server flips to accepting sign-ins.
func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	var request tokenRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	switch err := s.creds.Setup(request.Password); err {
	case nil:
		writeJSON(w, http.StatusCreated, authStatusBody{Initialized: true})
	case credential.ErrAlreadyInitialized:
		writeError(w, http.StatusConflict, "already_initialized",
			"this server already has a password; it cannot be set up again")
	case credential.ErrWeakPassword:
		writeError(w, http.StatusBadRequest, "weak_password", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "setup_failed", err.Error())
	}
}
