//go:build linux

package collectors

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// mongoCLI returns the mongo shell to use (mongosh preferred, legacy mongo as a
// fallback), or "" if neither is installed (so a non-Mongo service on 27017 isn't
// mislabelled).
func mongoCLI() string {
	for _, bin := range []string{"mongosh", "mongo"} {
		if _, err := exec.LookPath(bin); err == nil {
			return bin
		}
	}
	return ""
}

// MongoDBAvailable reports whether a local MongoDB server is installed (shell
// present) and its port (27017) is reachable.
func MongoDBAvailable() bool {
	if mongoCLI() == "" {
		return false
	}
	for _, addr := range []string{"127.0.0.1:27017", "[::1]:27017"} {
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			conn.Close() //nolint:errcheck
			return true
		}
	}
	return false
}

type MongoDBCollector struct{}

func NewMongoDBCollector() *MongoDBCollector { return &MongoDBCollector{} }

func (c *MongoDBCollector) Name() string           { return "MongoDB" }
func (c *MongoDBCollector) Timeout() time.Duration { return 8 * time.Second }

// mongoEvalScript collects identity, connection counts, and replica-set health in
// one round-trip, printed as a single JSON object.
const mongoEvalScript = `var o={};var h=db.hello();o.v=db.version();o.set=h.setName||"";` +
	`var c=db.serverStatus().connections;o.cc=c.current;o.ca=c.available;` +
	`if(o.set){try{var s=rs.status();` +
	`o.hp=s.members.some(function(m){return m.stateStr=="PRIMARY"});` +
	`o.dm=s.members.filter(function(m){return m.health===0}).length;` +
	`o.mn=s.members.length}catch(e){o.re=String(e)}}print(JSON.stringify(o))`

func (c *MongoDBCollector) Collect(ctx context.Context) (interface{}, error) {
	cli := mongoCLI()
	if cli == "" {
		return &models.MongoDBInfo{Detected: false}, nil
	}
	info := &models.MongoDBInfo{Detected: true}

	out, err := runCmd(ctx, cli, "--quiet", "--eval", mongoEvalScript)
	if err != nil {
		info.StatusReason = "mongo metrics unavailable (authentication required, or the shell could not connect)"
		return info, nil
	}
	parseMongoEval(out, info)
	return info, nil
}

func parseMongoEval(out string, info *models.MongoDBInfo) {
	// The JSON object is the last line that looks like one (mongosh may print
	// connection notices first).
	var line string
	for _, l := range strings.Split(out, "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
			line = t
		}
	}
	if line == "" {
		info.StatusReason = "mongo metrics response could not be parsed"
		return
	}
	var r struct {
		V   string `json:"v"`
		Set string `json:"set"`
		CC  int    `json:"cc"`
		CA  int    `json:"ca"`
		HP  bool   `json:"hp"`
		DM  int    `json:"dm"`
		MN  int    `json:"mn"`
	}
	if json.Unmarshal([]byte(line), &r) != nil {
		info.StatusReason = "mongo metrics response could not be parsed"
		return
	}
	info.MetricsRead = true
	info.Version = r.V
	info.ConnCurrent = r.CC
	info.ConnAvailable = r.CA
	if r.Set != "" {
		info.IsReplicaSet = true
		info.ReplicaSetName = r.Set
		info.HasPrimary = r.HP
		info.DownMembers = r.DM
		info.Members = r.MN
	}
}
