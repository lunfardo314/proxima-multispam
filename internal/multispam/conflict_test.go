package multispam

import (
	"testing"

	"github.com/lunfardo314/proxima/ledger/base"
)

// senderPaceKeepTimestamps and senderPaceTolerance mirror the node's per-holder filter
// (txinput_queue: keepTimestamps / concentrationTolerance). It remembers the last few
// timestamps seen from a holder and rejects a new one that lands within the transaction pace
// of any of them.
const (
	senderPaceKeepTimestamps = 4
	senderPaceTolerance      = 1
)

// acceptedByNodePace replays the node's filter over a sequence of timestamps from one holder
// and returns how many would survive it. The filter runs before the transaction is persisted
// or gossiped, so a rejected member of a conflict set never reaches any memDAG — the set would
// silently degrade into a single transaction and the tool would test nothing.
func acceptedByNodePace(ts []base.LedgerTime, pace int64) int {
	var ring [senderPaceKeepTimestamps]int64
	var pos int
	accepted := 0
	for _, t := range ts {
		ticks := t.TicksSinceGenesis()
		near := 0
		for _, seen := range ring {
			if seen != 0 && abs(ticks-seen) < pace {
				near++
			}
		}
		if near < senderPaceTolerance {
			accepted++
		}
		ring[pos] = ticks
		pos = (pos + 1) % senderPaceKeepTimestamps
	}
	return accepted
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// A conflict set is worthless unless every one of its transactions reaches the network: each
// carries the tag-along that puts it in a different sequencer's backlog, and a set that loses
// members loses exactly the sequencers it was meant to pull apart. This pins the spacing
// conflictTimestamps produces against the node-side filter.
func TestConflictSetSurvivesSenderPace(t *testing.T) {
	const pace = 12 // the ledger's non-sequencer TransactionPace

	for _, fanout := range []int{2, 3, 5, 8} {
		first := base.T(1000, 30)
		ts := conflictTimestamps(first, fanout, pace)

		if n := acceptedByNodePace(ts, pace); n != fanout {
			t.Fatalf("fanout %d: only %d of %d transactions would be accepted by the node", fanout, n, fanout)
		}

		// Consecutive sets must not collide either. The round waits until one pace past its
		// last transaction, so the next set starts there in the worst case.
		next := conflictTimestamps(ts[len(ts)-1].AddTicks(pace), fanout, pace)
		if n := acceptedByNodePace(append(ts, next...), pace); n != 2*fanout {
			t.Fatalf("fanout %d: back-to-back sets lose transactions, %d of %d accepted", fanout, n, 2*fanout)
		}
	}
}

// Half a pace apart is what a naive implementation produces, and the node collapses it to one
// transaction per pace window. Guards the test above against passing for the wrong reason.
func TestTooTightConflictSetIsRejected(t *testing.T) {
	const pace = 12

	ts := conflictTimestamps(base.T(1000, 30), 5, pace/2)
	if n := acceptedByNodePace(ts, pace); n >= 5 {
		t.Fatalf("expected the node filter to drop members of a half-pace set, %d of 5 accepted", n)
	}
}
