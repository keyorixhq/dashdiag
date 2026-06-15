package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckRabbitMQ(t *testing.T) {
	if got := checkRabbitMQ(models.RabbitMQInfo{Detected: false}); got != nil {
		t.Errorf("undetected rabbitmq should be silent, got %+v", got)
	}

	// AMQP up but diagnostics unreadable → INFO, never a silent OK.
	noDiag := checkRabbitMQ(models.RabbitMQInfo{Detected: true, Accepting: true, DiagnosticsRead: false})
	if !insightWithMsg(noDiag, "INFO", "diagnostics could not be read") {
		t.Errorf("unreadable diagnostics should be INFO, got %+v", noDiag)
	}

	// Healthy (pinged, alarms read, no alarms active) → silent.
	healthy := checkRabbitMQ(models.RabbitMQInfo{Detected: true, Accepting: true, DiagnosticsRead: true, Pinged: true, AlarmsRead: true})
	if len(healthy) != 0 {
		t.Errorf("healthy rabbitmq should be silent, got %+v", healthy)
	}

	// ping succeeded (DiagnosticsRead) but the alarms query failed → WARN, never a
	// silent OK: a publisher-blocking alarm can't be ruled out when it wasn't read.
	noAlarms := checkRabbitMQ(models.RabbitMQInfo{Detected: true, Accepting: true, DiagnosticsRead: true, Pinged: true, AlarmsRead: false})
	if !insightWithMsg(noAlarms, "WARN", "resource-alarm state could not be read") {
		t.Errorf("unread alarm state should WARN, got %+v", noAlarms)
	}

	// Memory alarm → CRIT (publishers blocked).
	mem := checkRabbitMQ(models.RabbitMQInfo{Detected: true, DiagnosticsRead: true, AlarmsRead: true, MemoryAlarm: true, AlarmDetail: "memory resource limit alarm on rabbit@h"})
	if !insightWithMsg(mem, "CRIT", "BLOCKING publishers") {
		t.Fatalf("memory alarm should CRIT, got %+v", mem)
	}
	if !insightWithMsg(mem, "CRIT", "memory resource alarm") {
		t.Errorf("CRIT should name the memory alarm, got %+v", mem)
	}

	// Disk alarm → CRIT, names disk.
	disk := checkRabbitMQ(models.RabbitMQInfo{Detected: true, DiagnosticsRead: true, AlarmsRead: true, DiskAlarm: true})
	if !insightWithMsg(disk, "CRIT", "disk resource alarm") {
		t.Errorf("disk alarm should CRIT naming disk, got %+v", disk)
	}
}
