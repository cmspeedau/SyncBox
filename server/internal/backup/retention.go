package backup

import (
	"fmt"
	"sort"
	"time"
)

// Policy is a grandfather/father/son ladder: keep the last N hourly snapshots, the
// last N daily ones, and so on. The effect is fine-grained recent history and
// coarse old history, so a mistake found on Monday is recoverable to the minute and
// one found in six months is recoverable to the month — without paying to keep
// every hour for six months.
//
// A zero or negative count disables that tier entirely, which is how a deployment
// that only wants daily and weekly backups turns hourly retention off.
type Policy struct {
	Hourly  int `json:"hourly"`
	Daily   int `json:"daily"`
	Weekly  int `json:"weekly"`
	Monthly int `json:"monthly"`
}

// DefaultPolicy is the ladder a new server starts with: about a day of hourly, a
// week of daily, two months of weekly, and a year of monthly.
func DefaultPolicy() Policy {
	return Policy{Hourly: 24, Daily: 7, Weekly: 8, Monthly: 12}
}

// buckets names the four tiers a snapshot falls into.
type buckets struct {
	hour  string
	day   string
	week  string
	month string
}

// bucketOf places a snapshot's timestamp into its four buckets.
func bucketOf(at time.Time) buckets {
	utc := at.UTC()
	year, week := utc.ISOWeek()
	return buckets{
		hour:  fmt.Sprintf("h:%s", utc.Format("2006-01-02T15")),
		day:   fmt.Sprintf("d:%s", utc.Format("2006-01-02")),
		week:  fmt.Sprintf("w:%04d-%02d", year, week),
		month: fmt.Sprintf("m:%s", utc.Format("2006-01")),
	}
}

// Prune decides which snapshots a policy keeps.
//
// Each tier keeps what its name says:
//
//   - Hourly keeps the newest N snapshots, full stop.
//   - Daily keeps the newest snapshot in each day bucket, for the N most recent
//     day buckets that have one. Weekly and Monthly work the same way over their
//     buckets.
//
// A snapshot is kept if any tier claims it, and being claimed by one tier does not
// stop another from claiming it: the newest snapshot of a day is also the newest
// snapshot overall, and both tiers want exactly that one. Tiers with a zero or
// negative count are off.
//
// It is a pure function over the snapshot list, so the decision can be tested
// without a filesystem and previewed before anything is deleted.
func Prune(snapshots []Snapshot, policy Policy) (kept, dropped []Snapshot) {
	ordered := append([]Snapshot(nil), snapshots...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].CreatedAt.After(ordered[j].CreatedAt)
	})

	claimed := make(map[string]bool, len(ordered))
	bucketsTaken := make(map[string]int, 4)

	// take claims one bucket for one tier. Seeing a bucket marks it whether or not
	// it was claimed, so the second snapshot of a day is never mistaken for that
	// day's representative.
	take := func(tier, bucket string, limit int) bool {
		if limit <= 0 {
			return false
		}
		key := tier + "\x00" + bucket
		if claimed[key] {
			return false
		}
		claimed[key] = true
		if bucketsTaken[tier] >= limit {
			return false
		}
		bucketsTaken[tier]++
		return true
	}

	for _, snapshot := range ordered {
		b := bucketOf(snapshot.CreatedAt)

		// The hourly tier is a plain quota over the whole list, so every snapshot
		// is its own bucket there.
		hourly := take("hour", snapshot.ID, policy.Hourly)
		daily := take("day", b.day, policy.Daily)
		weekly := take("week", b.week, policy.Weekly)
		monthly := take("month", b.month, policy.Monthly)

		if hourly || daily || weekly || monthly {
			kept = append(kept, snapshot)
			continue
		}
		dropped = append(dropped, snapshot)
	}
	return kept, dropped
}
