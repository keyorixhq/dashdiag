//go:build linux

package collectors

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
	"github.com/keyorixhq/dashdiag/internal/source"
)

func TestMongoDBCollectorIdentity(t *testing.T) {
	t.Parallel()
	c := NewMongoDBCollector()
	if c.Name() != "MongoDB" {
		t.Errorf("Name() = %q, want MongoDB", c.Name())
	}
	if c.Timeout() != 8*time.Second {
		t.Errorf("Timeout() = %v, want 8s", c.Timeout())
	}
}

func TestMongoCLI(t *testing.T) {
	t.Run("mongosh preferred", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/mongosh": []byte("/usr/bin/mongosh"),
			"lookpath/mongo":   []byte("/usr/bin/mongo"),
		}, nil, nil)
		if got := mongoCLI(); got != "mongosh" {
			t.Errorf("mongoCLI() = %q, want mongosh preferred over legacy mongo", got)
		}
	})

	t.Run("legacy mongo fallback", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/mongo": []byte("/usr/bin/mongo"),
		}, nil, nil)
		if got := mongoCLI(); got != "mongo" {
			t.Errorf("mongoCLI() = %q, want legacy mongo fallback", got)
		}
	})

	t.Run("neither installed", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, nil)
		if got := mongoCLI(); got != "" {
			t.Errorf("mongoCLI() = %q, want empty when neither shell is installed", got)
		}
	})
}

func TestMongoDBAvailable(t *testing.T) {
	t.Run("no shell installed", func(t *testing.T) {
		withCombinedFixture(t, nil, nil, nil)
		if MongoDBAvailable() {
			t.Error("expected false when no mongo shell is installed")
		}
	})

	t.Run("shell installed but port unreachable", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/mongosh":         []byte("/usr/bin/mongosh"),
			"dial/tcp/127.0.0.1:27017": {'0'},
			"dial/tcp/[::1]:27017":     {'0'},
		}, nil, nil)
		if MongoDBAvailable() {
			t.Error("expected false when the shell is installed but the port is unreachable")
		}
	})

	t.Run("shell installed and reachable", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/mongosh":         []byte("/usr/bin/mongosh"),
			"dial/tcp/127.0.0.1:27017": {'1'},
		}, nil, nil)
		if !MongoDBAvailable() {
			t.Error("expected true when the shell is installed and 127.0.0.1:27017 is reachable")
		}
	})

	t.Run("reachable only via ::1", func(t *testing.T) {
		withCombinedFixture(t, map[string][]byte{
			"lookpath/mongosh":         []byte("/usr/bin/mongosh"),
			"dial/tcp/127.0.0.1:27017": {'0'},
			"dial/tcp/[::1]:27017":     {'1'},
		}, nil, nil)
		if !MongoDBAvailable() {
			t.Error("expected true when only the ::1 address is reachable")
		}
	})
}

func TestMongoDBCollector_Collect_NotDetected(t *testing.T) {
	withCombinedFixture(t, nil, nil, nil)
	c := NewMongoDBCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MongoDBInfo)
	if info.Detected {
		t.Errorf("info = %+v, want Detected=false", info)
	}
}

func TestMongoDBCollector_Collect_EvalFails(t *testing.T) {
	withCombinedFixture(t, map[string][]byte{
		"lookpath/mongosh": []byte("/usr/bin/mongosh"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("mongosh", []string{"--quiet", "--eval", mongoEvalScript}, "", 1)
	})
	c := NewMongoDBCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MongoDBInfo)
	if !info.Detected {
		t.Fatal("Detected = false, want true")
	}
	if info.StatusReason == "" {
		t.Error("expected a StatusReason when the mongo shell eval fails")
	}
}

func TestMongoDBCollector_Collect_HappyPath(t *testing.T) {
	out := `{"v":"7.0.5","set":"rs0","cc":3,"ca":900,"hp":true,"dm":0,"mn":3}`
	withCombinedFixture(t, map[string][]byte{
		"lookpath/mongosh": []byte("/usr/bin/mongosh"),
	}, nil, func(b *source.Bundle) {
		b.PutCmd("mongosh", []string{"--quiet", "--eval", mongoEvalScript}, out, 0)
	})
	c := NewMongoDBCollector()
	raw, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	info := raw.(*models.MongoDBInfo)
	if !info.Detected || !info.MetricsRead {
		t.Fatalf("info = %+v, want Detected=true MetricsRead=true", info)
	}
	if info.Version != "7.0.5" || !info.IsReplicaSet || info.ReplicaSetName != "rs0" {
		t.Errorf("info mismatch: %+v", info)
	}
	if !info.ReplStatusRead || !info.HasPrimary || info.Members != 3 {
		t.Errorf("replica status mismatch: %+v", info)
	}
}

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
