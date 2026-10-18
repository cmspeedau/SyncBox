package api

// Rotating the server password once it exists. First run (firstrun.go) gives a
// fresh server its first credential; this is the door for every password after
// that. Unlike setup it is authenticated — you are already signed in — but it
// asks for the current password again as a second confirmation, so a stolen or
// forgotten bearer token is not, by itself, enough to lock the owner out by
// changing the password out from under them.

import (
	"net/http"

	"github.com/syncbox/server/internal/credential"
)

// changePasswordRequest carries both halves: the current password, to prove the
// caller is not just holding a token, and the new one to seal in its place.
type changePasswordRequest struct {
	Current  string `json:"current"`
	Password string `json:"password"`
}

// handleChangePassword rotates the stored password. It re-checks the current one
// server-side (the authority verifies against the Argon2id seal, so a wrong
// current password is caught here whatever the client checked first), seals the
// new one, and only writes durable once every check has passed. An environment
// password is refused rather than silently shadowed: SYNCBOX_PASSWORD is the
// source of truth in that deployment, and a change that vanished on the next
// restart would be worse than no change at all.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var request changePasswordRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	switch err := s.creds.Change(request.Current, request.Password); err {
	case nil:
		writeJSON(w, http.StatusOK, map[string]bool{"changed": true})
	case credential.ErrWrongPassword:
		// A valid token but the wrong current password. 403, not 401, so the
		// console reads it as a rejected change and keeps the session alive.
		writeError(w, http.StatusForbidden, "password_mismatch",
			"the current password did not match")
	case credential.ErrEnvPassword:
		writeError(w, http.StatusForbidden, "env_password",
			"this server's password comes from SYNCBOX_PASSWORD; change it there and restart")
	case credential.ErrWeakPassword:
		writeError(w, http.StatusBadRequest, "weak_password", err.Error())
	case credential.ErrNotInitialized:
		writeError(w, http.StatusConflict, "not_initialized",
			"this server has no password yet; complete first-run setup instead")
	default:
		writeError(w, http.StatusInternalServerError, "change_failed", err.Error())
	}
}
