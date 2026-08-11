package analysis

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

const (
	mongoCat           = "MongoDB"
	mongoInspectRSStat = "to inspect: mongosh --quiet --eval 'rs.status()'"
)

// checkMongoDB surfaces health for a local MongoDB server. Gated on Detected. The
// headline is replica-set health: a set with no PRIMARY can't accept writes.
// Never a silent OK when metrics couldn't be read.
func checkMongoDB(m models.MongoDBInfo) []models.Insight {
	if !m.Detected {
		return nil
	}
	if !m.MetricsRead {
		return []models.Insight{unverifiedInsight("INFO", mongoCat,
			"MongoDB is reachable, but its status could not be read",
			[]string{
				"note: pass credentials if auth is enabled (the mongo shell must be able to run db.serverStatus())",
				mongoInspectRSStat,
			},
		)}
	}

	var out []models.Insight

	// rs.status() couldn't be read (it's auth-gated separately) — we can't judge
	// primary/quorum. Say so honestly instead of firing the no-primary CRIT off an
	// unset HasPrimary (which would cry wolf on a healthy set).
	if m.IsReplicaSet && !m.ReplStatusRead {
		out = append(out, unverifiedInsight("INFO", mongoCat,
			fmt.Sprintf("replica set %q detected, but rs.status() could not be read — primary/quorum not verified", m.ReplicaSetName),
			[]string{
				"note: rs.status() may need credentials even when db.hello() does not",
				mongoInspectRSStat,
			}))
	} else if m.IsReplicaSet && !m.HasPrimary {
		// A replica set with no PRIMARY rejects all writes — a live outage.
		out = append(out, insight("CRIT", mongoCat,
			fmt.Sprintf("replica set %q has NO PRIMARY — writes are failing (election in progress or quorum lost)", m.ReplicaSetName),
			[]string{
				mongoInspectRSStat,
				"note: check member connectivity and that a majority of voting members are up",
			}))
	} else if m.DownMembers > 0 {
		// Has a primary but a member is unreachable — redundancy degraded.
		out = append(out, insight("WARN", mongoCat,
			fmt.Sprintf("%d of %d replica set member(s) unreachable — redundancy degraded", m.DownMembers, m.Members),
			[]string{
				"to inspect: mongosh --quiet --eval 'rs.status().members'",
				"note: a further member loss could cost the primary (no write quorum)",
			}))
	}

	// Connection saturation — at the limit, new connections are refused.
	if total := m.ConnCurrent + m.ConnAvailable; total > 0 {
		if ratio := float64(m.ConnCurrent) / float64(total); ratio >= 0.90 {
			out = append(out, insight("WARN", mongoCat,
				fmt.Sprintf("connections at %d/%d (%.0f%%) — approaching the limit", m.ConnCurrent, total, ratio*100),
				[]string{"to inspect: mongosh --quiet --eval 'db.serverStatus().connections'",
					"note: raise net.maxIncomingConnections, or add a connection pool / fewer clients"}))
		}
	}

	return out
}
