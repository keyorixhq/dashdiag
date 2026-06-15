package analysis

import (
	"testing"

	"github.com/keyorixhq/dashdiag/internal/models"
)

func TestCheckTraefik(t *testing.T) {
	if got := checkTraefik(models.TraefikInfo{Detected: false}); got != nil {
		t.Errorf("undetected traefik should be silent, got %+v", got)
	}

	// Up but API unreadable → INFO, never a silent OK.
	noAPI := checkTraefik(models.TraefikInfo{Detected: true, APIRead: false})
	if !insightWithMsg(noAPI, "INFO", "API could not be read") {
		t.Errorf("unreadable API should be INFO, got %+v", noAPI)
	}

	// Healthy (no errors) → silent.
	healthy := checkTraefik(models.TraefikInfo{Detected: true, APIRead: true, RoutersTotal: 6})
	if len(healthy) != 0 {
		t.Errorf("healthy traefik should be silent, got %+v", healthy)
	}

	// Routers in error → WARN.
	rerr := checkTraefik(models.TraefikInfo{Detected: true, APIRead: true, RoutersTotal: 6, RoutersErrors: 2})
	if !insightWithMsg(rerr, "WARN", "2 of 6 HTTP router(s) are in ERROR") {
		t.Fatalf("router errors should WARN, got %+v", rerr)
	}

	// Service/middleware errors → WARN (separate insight).
	serr := checkTraefik(models.TraefikInfo{Detected: true, APIRead: true, RoutersTotal: 3, ServicesErrors: 1, MiddlewareErrors: 2})
	if !insightWithMsg(serr, "WARN", "1 service error(s) and 2 middleware error(s)") {
		t.Errorf("service/middleware errors should WARN, got %+v", serr)
	}

	// Warnings only (no errors) → silent (warnings aren't outages).
	warnOnly := checkTraefik(models.TraefikInfo{Detected: true, APIRead: true, RoutersTotal: 4, RoutersWarnings: 2})
	if len(warnOnly) != 0 {
		t.Errorf("router warnings without errors should be silent, got %+v", warnOnly)
	}
}
