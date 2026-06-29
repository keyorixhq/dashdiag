package render

import (
	"fmt"

	"github.com/keyorixhq/dashdiag/internal/models"
)

// Inline row summaries for the RHEL/Oracle maintenance checks. Each returns "" when
// the subsystem is absent so the row is hidden on hosts that don't run it.

func inlineKdump(data interface{}) string {
	var k *models.KdumpInfo
	if v, ok := data.(*models.KdumpInfo); ok {
		k = v
	} else if v, ok := data.(models.KdumpInfo); ok {
		k = &v
	}
	if k == nil || !k.Available {
		return ""
	}
	if !k.Enabled {
		return "off"
	}
	if k.CrashLoaded && k.ReservedBytes > 0 {
		return fmt.Sprintf("armed (%dM reserved)", k.ReservedBytes/(1024*1024))
	}
	return "NOT armed"
}

func inlineTuned(data interface{}) string {
	var t *models.TunedInfo
	if v, ok := data.(*models.TunedInfo); ok {
		t = v
	} else if v, ok := data.(models.TunedInfo); ok {
		t = &v
	}
	if t == nil || !t.Available {
		return ""
	}
	if !t.Active {
		return "inactive"
	}
	return t.Profile
}

func inlineKernelPatch(data interface{}) string {
	var k *models.KernelPatchInfo
	if v, ok := data.(*models.KernelPatchInfo); ok {
		k = v
	} else if v, ok := data.(models.KernelPatchInfo); ok {
		k = &v
	}
	if k == nil || !k.Available {
		return ""
	}
	if k.RebootNeeded {
		return "reboot pending"
	}
	return ""
}

func inlineKsplice(data interface{}) string {
	var k *models.KspliceInfo
	if v, ok := data.(*models.KspliceInfo); ok {
		k = v
	} else if v, ok := data.(models.KspliceInfo); ok {
		k = &v
	}
	if k == nil || !k.Available {
		return ""
	}
	if k.PendingUpdates > 0 {
		return fmt.Sprintf("%d pending", k.PendingUpdates)
	}
	if k.Patched {
		return "live-patched"
	}
	return ""
}

func inlineServiceRestart(data interface{}) string {
	var s *models.ServiceRestartInfo
	if v, ok := data.(*models.ServiceRestartInfo); ok {
		s = v
	} else if v, ok := data.(models.ServiceRestartInfo); ok {
		s = &v
	}
	if s == nil || !s.Available {
		return ""
	}
	if s.StaleCount > 0 {
		return fmt.Sprintf("%d need restart", s.StaleCount)
	}
	if s.NeedsRoot {
		return "partial (needs root)"
	}
	return ""
}
