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
}

func (s *Server) handleAbout(w http.ResponseWriter, r *http.Request) {
	version := s.version
	if version == "" {
		version = "dev"
	}
	body := aboutBody{
		Version:     version,
		Storage:     s.storage,
		DataDir:     s.dataDir,
		ShareTTL:    int(s.shareTTL / time.Second),
		RecycleDays: s.recycleDays,
	}
	if s.backups != nil {
		body.BackupsConfigured = true
		body.BackupTarget = s.backups.Location()
	}
	writeJSON(w, http.StatusOK, body)
}
