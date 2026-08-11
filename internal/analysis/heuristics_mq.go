package analysis

import "github.com/keyorixhq/dashdiag/internal/models"

const (
	mqCatRabbitMQ   = "RabbitMQ"
	mqInspectAlarms = "to inspect: rabbitmq-diagnostics alarms"
)

// checkRabbitMQ surfaces health issues for a local RabbitMQ broker. Gated on
// Detected. The headline is a resource alarm: when RabbitMQ crosses its memory or
// disk watermark it BLOCKS all publishers, so messages silently stop being
// accepted — a live outage. Never a silent OK when diagnostics couldn't run.
func checkRabbitMQ(r models.RabbitMQInfo) []models.Insight {
	if !r.Detected {
		return nil
	}

	if !r.DiagnosticsRead {
		return []models.Insight{unverifiedInsight("INFO", mqCatRabbitMQ,
			"RabbitMQ's AMQP port is up, but diagnostics could not be read",
			[]string{
				"note: run dsd as root or the rabbitmq user (needs the Erlang cookie) for alarm and node checks",
				mqInspectAlarms,
			},
		)}
	}

	// ping (→ DiagnosticsRead) confirmed access, but the alarms query itself failed,
	// so the alarm state — the headline publisher-blocking signal — was never read.
	// Surfacing this as WARN keeps a failed alarms read from passing as a clean broker.
	if !r.AlarmsRead {
		return []models.Insight{unverifiedInsight("WARN", mqCatRabbitMQ,
			"RabbitMQ is up but its resource-alarm state could not be read — a publisher-blocking memory/disk alarm cannot be ruled out",
			[]string{
				mqInspectAlarms,
				"note: the alarms query failed even though ping succeeded — retry, or check the rabbitmq-diagnostics version",
			},
		)}
	}

	if r.MemoryAlarm || r.DiskAlarm {
		which := "memory"
		switch {
		case r.MemoryAlarm && r.DiskAlarm:
			which = "memory and disk"
		case r.DiskAlarm:
			which = "disk"
		}
		msg := "RabbitMQ " + which + " resource alarm is active — the broker is BLOCKING publishers; messages are not being accepted"
		if r.AlarmDetail != "" {
			msg += " (" + r.AlarmDetail + ")"
		}
		return []models.Insight{insight("CRIT", mqCatRabbitMQ, msg,
			[]string{
				mqInspectAlarms,
				"to fix (memory): free RAM / raise vm_memory_high_watermark, or drain a backed-up queue",
				"to fix (disk): free disk space below the disk_free_limit",
			})}
	}

	return nil
}
