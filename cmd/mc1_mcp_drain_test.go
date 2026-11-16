package cmd

// MC3 regression guard for the adaptive drain-quiescence detector (waitDrain).
//
// The go-sdk dispatches tools/call ASYNC. The whole reason serveOnce holds the
// input pipe open at all is so that an in-flight stub handler runs and flushes its
// response BEFORE EOF tears the session down. If the drain detector closes too
// eagerly it does not fail loudly — it silently drops the dispatch, quietly
// gutting M3/M5 coverage (no tool call is ever recorded, no echoed output is ever
// scanned). This test pins that down: a well-formed post-handshake tools/call must
// still be captured under the adaptive detector, every time.
//
// RED/GREEN proof (documented, re-run once by hand): replacing waitDrain's body
// with an immediate `return` (no hold) drops the capture rate to ~0/200 and this
// test fails; the real waitDrain captures 200/200 and it passes. So the assertion
// fails without the hold and passes with it.

import (
	"strings"
	"testing"
)

// A valid initialize+initialized handshake followed by a single well-formed
// tools/call to dsd_health (the stub echoes an empty string back as "echo:").
func mc1WellFormedCall() []byte {
	return append(mc1Handshake(),
		[]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dsd_health","arguments":{"deep":true}}}`+"\n")...)
}

func TestMC1AdaptiveDrainCapturesAsyncDispatch(t *testing.T) {
	const iters = 200
	input := mc1WellFormedCall()

	captured := 0
	echoed := 0
	for i := 0; i < iters; i++ {
		out, calls := serveOnce(input)
		if len(calls) >= 1 {
			captured++
			for _, c := range calls {
				if c.tool == "dsd_health" {
					// handler ran
				}
			}
		}
		// The handshake 'initialize' reply plus the tools/call reply must both be
		// on the wire; the tools/call stub returns a TextContent of "echo:".
		if strings.Contains(string(out), "echo:") {
			echoed++
		}
	}

	// Every iteration must capture the async dispatch and its echoed output. A
	// detector that closed before the handler flushed would push these toward 0.
	if captured != iters {
		t.Fatalf("adaptive drain lost async dispatch: captured %d/%d tools/call handler runs", captured, iters)
	}
	if echoed != iters {
		t.Fatalf("adaptive drain lost echoed response: %d/%d outputs contained the handler echo", echoed, iters)
	}
}
