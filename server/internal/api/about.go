package api

// The console's "About this server" facts. The name-card at "/" and the /healthz
// probe are both unauthenticated and answer "what is this port" — so they must
// not name the data directory or the backup location. This endpoint is the
// authenticated counterpart the operator reaches for: everything the environment
// pointed the server at that has no other home in the console. Read-only, and it
// leaks no credential (the backup target is the safe Location label, never the
// keys behind it).

import (
	"net/http"
	"time"
)

// aboutBody is the read-only deployment summary.
type aboutBody struct {
	Version  string `json:"version"`
	Storage  string `json:"storage"`
	DataDir  string `json:"data_dir"`
	ShareTTL int    `json:"share_ttl_seconds"`
	// RecycleDays is how long a deletion stays restorable; zero means the
	// recycle bin keeps everything until it is purged by hand.
	RecycleDays int `json:"recycle_days"`
	// BackupTarget is the target's safe label (a directory or s3:// URL), empty
	// when no backup target is configured.
	BackupTarget      string `json:"backup_target"`
	BackupsConfigured bool   `json:"backups_configured"`
	// Posture the environment chose that the console would otherwise have no way
	// to read back: how long a signed-in session lasts, whether calls are throttled
	// (and how hard), and whether a commit to an unregistered vault is refused.
	TokenTTLSeconds   int     `json:"token_ttl_seconds"`
	RateLimitRPS      float64 `json:"rate_limit_rps,omitempty"`
	RateBurst         int     `json:"rate_burst,omitempty"`
	RequireRegistered bool    `json:"require_registered_vaults"`
}

func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	version := s.version
	if version == "" {
		version = "dev"
	}
	body := aboutBody{
		Version:           version,
		Storage:           s.storage,
		DataDir:           s.dataDir,
		ShareTTL:          int(s.shareTTL / time.Second),
		RecycleDays:       s.recycleDays,
		TokenTTLSeconds:   int(s.issuer.TTL() / time.Second),
		RequireRegistered: s.requireRegisteredVaults,
	}
	if s.rateLimit > 0 {
		body.RateLimitRPS = s.rateLimit
		body.RateBurst = s.rateBurst
	}
	if s.backups != nil {
		body.BackupsConfigured = true
		body.BackupTarget = s.backups.Location()
	}
	writeJSON(w, http.StatusOK, body)
}
