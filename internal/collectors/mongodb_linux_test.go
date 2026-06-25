//go:build linux

package collectors

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestParseMongoEval(t *testing.T) {
	t.Run("rs.status() threw → ReplStatusRead false, HasPrimary not asserted", func(t *testing.T) {
		// db.hello() returned the set name, but rs.status() threw (auth-gated): the
		// `re` field is present and hp/mn are absent. The false-CRIT trap.
		out := `{"v":"7.0.5","set":"rs0","cc":3,"ca":900,"re":"MongoServerError: not authorized on admin to execute command"}`
		var info models.MongoDBInfo
		parseMongoEval(out, &info)
		if !info.MetricsRead {
			t.Fatal("MetricsRead should be true (the eval itself parsed)")
		}
		if !info.IsReplicaSet {
			t.Fatal("IsReplicaSet should be true (set name present)")
		}
		if info.ReplStatusRead {
			t.Error("ReplStatusRead should be FALSE when rs.status() threw")
		}
		if info.HasPrimary {
			t.Error("HasPrimary must not be asserted from a failed rs.status() read")
		}
	})

	t.Run("healthy primary → ReplStatusRead true", func(t *testing.T) {
		out := `{"v":"7.0.5","set":"rs0","cc":3,"ca":900,"hp":true,"dm":0,"mn":3}`
		var info models.MongoDBInfo
		parseMongoEval(out, &info)
		if !info.ReplStatusRead || !info.HasPrimary || info.Members != 3 {
			t.Errorf("healthy: got ReplStatusRead=%v HasPrimary=%v Members=%d, want true/true/3",
				info.ReplStatusRead, info.HasPrimary, info.Members)
		}
	})

	t.Run("genuine no primary (status read) → HasPrimary false but ReplStatusRead true", func(t *testing.T) {
		out := `{"v":"7.0.5","set":"rs0","cc":3,"ca":900,"hp":false,"dm":1,"mn":3}`
		var info models.MongoDBInfo
		parseMongoEval(out, &info)
		if !info.ReplStatusRead {
			t.Error("ReplStatusRead should be true (rs.status() returned)")
		}
		if info.HasPrimary {
			t.Error("HasPrimary should be false (genuine no-primary)")
		}
	})

	t.Run("standalone → not a replica set", func(t *testing.T) {
		out := `{"v":"7.0.5","set":"","cc":2,"ca":900}`
		var info models.MongoDBInfo
		parseMongoEval(out, &info)
		if info.IsReplicaSet || info.ReplStatusRead {
			t.Errorf("standalone: IsReplicaSet=%v ReplStatusRead=%v, want both false", info.IsReplicaSet, info.ReplStatusRead)
		}
	})
}
