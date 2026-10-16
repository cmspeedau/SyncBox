package backup

import (
	"fmt"
	"testing"
	"time"
)

// hourly makes n snapshots at hourly intervals from start.
func hourly(n int, start time.Time) []Snapshot {
	out := make([]Snapshot, 0, n)
	for i := 0; i < n; i++ {
		at := start.Add(time.Duration(i) * time.Hour)
		out = append(out, Snapshot{
			ID:        fmt.Sprintf("%s-%04d", at.UTC().Format("2006-01-02T150405Z"), i),
			CreatedAt: at,
		})
	}
	return out
}

func ids(snapshots []Snapshot) []string {
	out := make([]string, 0, len(snapshots))
	for _, snapshot := range snapshots {
		out = append(out, snapshot.ID)
	}
	return out
}

func TestPruneKeepsTheNewestWithinEachTier(t *testing.T) {
	start := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		policy      Policy
		snapshots   []Snapshot
		wantKept    int
		wantDropped int
	}{
		{
			name:        "hourly tier caps the rest",
			policy:      Policy{Hourly: 2},
			snapshots:   hourly(6, start),
			wantKept:    2,
			wantDropped: 4,
		},
		{
			name:        "hourly off leaves one per day",
			policy:      Policy{Daily: 1},
			snapshots:   hourly(6, start),
			wantKept:    1,
			wantDropped: 5,
		},
		{
			name:   "a representative per day, when both days have a slot",
			policy: Policy{Daily: 2},
			snapshots: append(hourly(3, start),
				hourly(3, start.Add(24*time.Hour))...),
			wantKept:    2,
			wantDropped: 4,
		},
		{
			name:   "one day slot only reaches the most recent day",
			policy: Policy{Daily: 1},
			snapshots: append(hourly(3, start),
				hourly(3, start.Add(24*time.Hour))...),
			wantKept:    1,
			wantDropped: 5,
		},
		{
			name:        "a zero policy keeps nothing",
			policy:      Policy{},
			snapshots:   hourly(4, start),
			wantKept:    0,
			wantDropped: 4,
		},
		{
			name:   "a representative per month across a year",
			policy: Policy{Monthly: 14},
			snapshots: func() []Snapshot {
				out := make([]Snapshot, 0, 14)
				for i := 0; i < 14; i++ {
					at := start.AddDate(0, i, 0)
					out = append(out, Snapshot{ID: at.Format("2006-01-02"), CreatedAt: at})
				}
				return out
			}(),
			wantKept:    14,
			wantDropped: 0,
		},
		{
			name:   "one month slot reaches only the newest month",
			policy: Policy{Monthly: 1},
			snapshots: func() []Snapshot {
				out := make([]Snapshot, 0, 14)
				for i := 0; i < 14; i++ {
					at := start.AddDate(0, i, 0)
					out = append(out, Snapshot{ID: at.Format("2006-01-02"), CreatedAt: at})
				}
				return out
			}(),
			wantKept:    1,
			wantDropped: 13,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			kept, dropped := Prune(test.snapshots, test.policy)
			if len(kept) != test.wantKept {
				t.Errorf("kept %d snapshots %v, want %d", len(kept), ids(kept), test.wantKept)
			}
			if len(dropped) != test.wantDropped {
				t.Errorf("dropped %d snapshots, want %d", len(dropped), test.wantDropped)
			}
			if len(kept)+len(dropped) != len(test.snapshots) {
				t.Errorf("kept %d + dropped %d != input %d", len(kept), len(dropped), len(test.snapshots))
			}
		})
	}
}

func TestPruneReturnsNewestFirst(t *testing.T) {
	start := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	// Deliberately shuffled: the caller's order must not decide what survives.
	input := []Snapshot{
		{ID: "third", CreatedAt: start.Add(2 * time.Hour)},
		{ID: "first", CreatedAt: start},
		{ID: "second", CreatedAt: start.Add(time.Hour)},
	}

	kept, _ := Prune(input, Policy{Hourly: 2})
	got := ids(kept)
	if len(got) != 2 || got[0] != "third" || got[1] != "second" {
		t.Errorf("kept = %v, want [third second]", got)
	}
}

func TestPruneLeavesTheInputAlone(t *testing.T) {
	start := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	input := hourly(5, start)
	before := ids(input)

	Prune(input, Policy{Hourly: 1})

	after := ids(input)
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("Prune reordered the caller's slice: %v became %v", before, after)
		}
	}
}

func TestBucketOfUsesUTCAndISOWeeks(t *testing.T) {
	// 2026-01-01 is a Thursday in ISO week 1; the week bucket must follow the
	// ISO calendar rather than an arbitrary seven-day window from the epoch.
	at := time.Date(2026, 1, 1, 23, 30, 0, 0, time.FixedZone("UTC+9", 9*60*60))
	b := bucketOf(at)

	if b.hour != "h:2026-01-01T14" {
		t.Errorf("hour bucket = %q, want h:2026-01-01T14", b.hour)
	}
	if b.day != "d:2026-01-01" {
		t.Errorf("day bucket = %q, want d:2026-01-01", b.day)
	}
	if b.week != "w:2026-01" {
		t.Errorf("week bucket = %q, want w:2026-01", b.week)
	}
	if b.month != "m:2026-01" {
		t.Errorf("month bucket = %q, want m:2026-01", b.month)
	}
}

func TestDefaultPolicyShapesAYear(t *testing.T) {
	policy := DefaultPolicy()
	if policy.Hourly != 24 || policy.Daily != 7 || policy.Weekly != 8 || policy.Monthly != 12 {
		t.Errorf("DefaultPolicy = %+v, want {24 7 8 12}", policy)
	}
}
