package api

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/syncbox/server/internal/store"
)

// handleEvents long-polls a vault for change notifications.
//
// It answers with the same revision page the revisions endpoint returns, so the
// notification is a hint to read, not the change itself: a client that was away
// when a commit happened catches up by passing its last-seen revision as `since`,
// exactly as it would against GET .../revisions. It returns as soon as `since`
// would skip anything new, after a `wait` of no change, or when the client
// disconnects. That means correctness never depends on the in-process signal: a
// missed signal only costs a full `wait` before an empty-but-current reply.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
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
	wait, err := parseEventWait(r.URL.Query().Get("wait"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	// Subscribe before the first read so a commit landing between the read and the
	// wait below cannot be missed: its signal is already queued for us.
	signals := s.hub.subscribe(vaultID)
	defer s.hub.unsubscribe(vaultID, signals)

	var timeout <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}

	for {
		page, err := s.readRevisions(r.Context(), vaultID, since, int(limit))
		if err != nil {
			writeErrorFrom(w, err)
			return
		}
		if len(page.Revisions) > 0 || timeout == nil {
			// Either there is news to hand back, or the client asked us not to wait.
			writeJSON(w, http.StatusOK, page)
			return
		}
		select {
		case _, open := <-signals:
			if !open {
				// We were unsubscribed; give the client what we have rather than spin.
				writeJSON(w, http.StatusOK, page)
				return
			}
			// Loop to re-read; the signal only means "something may have changed".
		case <-timeout:
			page.Revisions = []store.Revision{}
			writeJSON(w, http.StatusOK, page)
			return
		case <-r.Context().Done():
			// The client hung up; there is no one left to answer.
			return
		}
	}
}

// readRevisions fetches one page of a vault's revisions. Both the revisions GET and
// the events long-poll go through it, so a client can catch up from either and the
// two can never disagree about what a page contains.
func (s *Server) readRevisions(ctx context.Context, vaultID string, since uint64, limit int) (revisionPage, error) {
	revisions, head, err := s.store.RevisionsSince(ctx, vaultID, since, limit)
	if err != nil {
		return revisionPage{}, err
	}
	return revisionPage{Revisions: revisions, Upto: head}, nil
}

// parseEventWait reads the optional wait parameter, defaulting and clamping it so a
// client cannot pin a handler open longer than the server is willing to hold.
func parseEventWait(raw string) (time.Duration, error) {
	if raw == "" {
		return DefaultEventWait, nil
	}
	wait, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("wait %q is not a duration", raw)
	}
	if wait < 0 {
		return 0, fmt.Errorf("wait must not be negative")
	}
	if wait > MaxEventWait {
		wait = MaxEventWait
	}
	return wait, nil
}

// hub fans out "this vault changed" signals to any long-poll waiting on it. It is
// in-process only: the server is one Go process, so a commit can wake waiters
// directly. A client that was not connected when a signal fired misses nothing,
// because the events endpoint answers with the actual revision page — it is a hint
// to re-read, never the change itself. That keeps correctness independent of the
// hub: a dropped signal only means the long-poll runs to its timeout and returns.
type hub struct {
	mu      sync.Mutex
	waiters map[string]map[chan struct{}]struct{}
}

func newHub() *hub {
	return &hub{waiters: make(map[string]map[chan struct{}]struct{})}
}

// subscribe registers a waiter for a vault. The channel is buffered to one and
// only ever receives non-blocking sends, so a slow or vanished waiter can never
// block a commit.
func (h *hub) subscribe(vaultID string) chan struct{} {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.waiters[vaultID]
	if set == nil {
		set = make(map[chan struct{}]struct{})
		h.waiters[vaultID] = set
	}
	set[ch] = struct{}{}
	return ch
}

// unsubscribe drops a waiter and closes its channel. Callers defer it so a
// disconnecting client does not leak.
func (h *hub) unsubscribe(vaultID string, ch chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set := h.waiters[vaultID]; set != nil {
		if _, ok := set[ch]; ok {
			delete(set, ch)
			if len(set) == 0 {
				delete(h.waiters, vaultID)
			}
			close(ch)
		}
	}
}

// publish wakes every waiter on a vault. Called after a commit is durable, so a
// woken waiter re-reads and sees the new revision.
func (h *hub) publish(vaultID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.waiters[vaultID] {
		select {
		case ch <- struct{}{}:
		default:
			// A signal is already pending for this waiter; one is enough, since the
			// waiter re-reads rather than counting changes.
		}
	}
}
