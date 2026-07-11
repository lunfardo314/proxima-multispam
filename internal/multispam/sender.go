package multispam

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math/rand"
	"sync/atomic"
	"time"

	"github.com/lunfardo314/proxima/api/client"
	"github.com/lunfardo314/proxima/ledger"
	"github.com/lunfardo314/proxima/ledger/base"
	"github.com/lunfardo314/proxima/ledger/txbuildercore"
)

// spentEntry tracks a UTXO that was consumed by a submitted transaction.
type spentEntry struct {
	TxID          base.TransactionID
	SubmittedSlot uint32
}

// spendable is a wallet-side consumable output: raw output wire-bytes +
// its OutputID + token amount. It decouples batch-chaining (consuming a
// tx's own remainder before it is confirmed) from *ledger.OutputWithID,
// so a produced output never needs to be parsed back through a ledger
// library — we already know its bytes, id and amount at build time.
type spendable struct {
	id     base.OutputID
	bytes  []byte
	amount uint64
}

// Sender is an autonomous goroutine that continuously sends transactions from one account.
type Sender struct {
	name       string
	index      int // position in the sender list (for "next" strategy)
	privateKey ed25519.PrivateKey
	account    ledger.SigLock // sigLock controller, used to query owned outputs
	holderID   base.HolderID

	// Wallet state (singleton-free): library for composing outputs and
	// constants for clock/pace math. Fetched once and shared read-only.
	lib       *txbuildercore.Library[any]
	constants *txbuildercore.Constants

	cfg       *Config
	hosts     []HostConfig
	hostIdx   int
	seqPicker *SequencerPicker
	targets   []base.HolderID // all sender holder IDs for target strategies
	// peerBalances is the per-sender last-known balance, index-aligned with `targets`
	// (shared, read atomically). Used by the "rebalance" target strategy to steer each
	// transfer toward a below-average sender so the spam traffic itself keeps the fund
	// distribution even — no separate rebalance pass. Wired by the coordinator after all
	// senders exist; nil until then (rebalance falls back to random).
	peerBalances []*SenderMetrics
	// lastFanoutSlot throttles rich-sender fan-out funding to once per
	// RebalanceIntervalSlots, so funding finalizes and balances re-read before the next
	// fan-out decision (else stale balances re-fund the same accounts and re-condense).
	lastFanoutSlot uint32
	spentSet       map[base.OutputID]spentEntry
	metrics        *SenderMetrics
	logFunc   func(format string, args ...any)
	verbose   bool

	// minStorageDeposit is the sigLock storage-deposit floor (computed once,
	// wallet-side). A produced sigLock output below it makes the tx invalid.
	minStorageDeposit uint64
}

// SenderMetrics holds per-sender counters, read atomically by the coordinator.
type SenderMetrics struct {
	TxSent      atomic.Int64
	TxFailed    atomic.Int64
	LastBalance atomic.Uint64
}

// SenderParams holds everything needed to create a Sender.
type SenderParams struct {
	Name       string
	Index      int
	PrivateKey ed25519.PrivateKey
	Config     *Config
	Library    *txbuildercore.Library[any]
	Constants  *txbuildercore.Constants
	SeqPicker  *SequencerPicker
	Targets    []base.HolderID
	LogFunc    func(format string, args ...any)
	Verbose    bool

	// MinStorageDeposit is the sigLock storage-deposit floor (see Sender).
	MinStorageDeposit uint64
}

func NewSender(par SenderParams) *Sender {
	return &Sender{
		name:       par.Name,
		index:      par.Index,
		privateKey: par.PrivateKey,
		account:    ledger.SigLockFromED25519PrivateKey(par.PrivateKey),
		holderID:   base.HolderIDFromED25519PrivateKey(par.PrivateKey),
		lib:        par.Library,
		constants:  par.Constants,
		cfg:        par.Config,
		hosts:      par.Config.APIHosts,
		seqPicker:  par.SeqPicker,
		targets:    par.Targets,
		spentSet:   make(map[base.OutputID]spentEntry),
		metrics:    &SenderMetrics{},
		logFunc:    par.LogFunc,
		verbose:    par.Verbose,

		minStorageDeposit: par.MinStorageDeposit,
	}
}

func (s *Sender) Metrics() *SenderMetrics { return s.metrics }
func (s *Sender) Name() string            { return s.name }

// SetPeerBalances wires the shared per-sender balance view (index-aligned with the
// target list) used by the "rebalance" target strategy.
func (s *Sender) SetPeerBalances(peers []*SenderMetrics) { s.peerBalances = peers }

// Run is the main sender loop. Blocks until context is cancelled.
func (s *Sender) Run(ctx context.Context) {
	pace := int(s.constants.TransactionPace)
	paceDuration := time.Duration(pace) * s.constants.TickDuration
	mindRateControl := s.cfg.IsMindRateControl()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sent := s.doRound(pace)
		if !sent || mindRateControl {
			// Wait pace duration: either nothing to spend, or respecting rate control
			select {
			case <-ctx.Done():
				return
			case <-time.After(paceDuration):
			}
		}
	}
}

// doRound performs one iteration: query outputs, classify, build and submit.
// Returns true if at least one transaction was submitted.
func (s *Sender) doRound(pace int) bool {
	clnt := s.client()

	// Step 1: Query LRB outputs
	outs, _, totalBalance, err := clnt.GetTransferableOutputs(s.account, 256)
	if err != nil {
		s.log("error fetching outputs: %v", err)
		s.rotateHost()
		return false
	}

	s.metrics.LastBalance.Store(totalBalance)

	// LRB membership set, for spentSet maintenance.
	lrbSet := make(map[base.OutputID]struct{}, len(outs))
	for _, o := range outs {
		lrbSet[o.ID] = struct{}{}
	}

	// Step 2: Classify outputs and maintain spentSet
	currentSlot := s.constants.LedgerTimeFromClockTime(time.Now()).Slot
	s.classifyOutputs(lrbSet, currentSlot, clnt)

	// Collect spendable outputs (in LRB and not in spentSet)
	var available []spendable
	var availableBalance uint64
	for _, o := range outs {
		if _, spent := s.spentSet[o.ID]; spent {
			continue
		}
		amt := o.Output.TokenBalance()
		available = append(available, spendable{id: o.ID, bytes: o.Output.Bytes(), amount: amt})
		availableBalance += amt
	}

	if len(available) == 0 {
		return false
	}

	// Step 3: Get sequencer for tag-along
	seqInfo, ok := s.seqPicker.Next()
	if !ok {
		s.log("no sequencers available")
		return false
	}

	// Step 3.5 (rebalance mode): if this sender is rich and starving accounts exist,
	// fund as many of them as its balance allows in ONE fan-out transaction. This
	// redistributes far faster than the per-round batch of single small transfers,
	// which cannot drain a large account or lift the frozen ones quickly enough.
	if s.cfg.Global.TargetStrategy == StrategyRebalance {
		if s.tryFanoutFunding(available, availableBalance, currentSlot, seqInfo, clnt) {
			return true
		}
	}

	// Step 4: Check minimum balance. A sender with funds below the floor for a
	// single valid transfer cannot transact without producing a dust remainder
	// (which the node silently rejects). This is expected while waiting for
	// funding to arrive, so only surface it under -v to avoid noise. Senders
	// with zero spendable outputs were already handled above and stay quiet.
	minForOneTx := s.cfg.MinBalanceForOneTx(seqInfo.Fee, s.minStorageDeposit)
	if availableBalance < minForOneTx {
		if s.verbose {
			s.log("UNDERFUNDED: spendable %d < minimum %d (transfer %d + fee %d + storage deposit %d) — fund this sender",
				availableBalance, minForOneTx, s.cfg.Global.TransferAmount, seqInfo.Fee, s.minStorageDeposit)
		}
		return false
	}

	// Step 5: Build and submit batch
	return s.buildAndSubmitBatch(available, pace, seqInfo, clnt)
}

// classifyOutputs updates the spentSet based on current LRB state.
func (s *Sender) classifyOutputs(lrbSet map[base.OutputID]struct{}, currentSlot uint32, clnt *client.APIClient) {
	finalitySlots := uint32(s.cfg.Global.FinalityTimeoutSlots)

	for oid, entry := range s.spentSet {
		if _, inLRB := lrbSet[oid]; !inLRB {
			// Output no longer in LRB — the spending tx was finalized (output consumed)
			// or the output itself was consumed by someone else. Either way, remove.
			delete(s.spentSet, oid)
			continue
		}
		// Output is still in LRB but we marked it spent. Check if spending tx finalized.
		_, foundAtDepth, err := clnt.CheckTransactionIDInLRB(entry.TxID, 1)
		if err != nil {
			// API error — leave as is for now
			continue
		}
		if foundAtDepth >= 0 {
			// Spending tx is in LRB — it's finalized, output should disappear soon
			delete(s.spentSet, oid)
			continue
		}
		// Spending tx not in LRB. Check if enough time has passed to reclaim.
		if currentSlot-entry.SubmittedSlot >= finalitySlots {
			// Reclaim: allow re-spending this output
			delete(s.spentSet, oid)
		}
	}
}

func (s *Sender) buildAndSubmitBatch(available []spendable, pace int, seqInfo SequencerInfo, clnt *client.APIClient) bool {
	batchSize := s.cfg.Global.BatchSize
	anySent := false

	// For batch > 1, we chain transactions: each tx consumes the remainder of the previous.
	// The first tx uses available UTXOs from the LRB.
	// Subsequent txs in the batch consume only the remainder output from the previous tx.

	currentInputs := available
	var remainderOutput *spendable // output from previous tx in the batch

	for txIdx := 0; txIdx < batchSize; txIdx++ {
		isLastInBatch := txIdx == batchSize-1

		var inputs []spendable
		if remainderOutput != nil {
			inputs = []spendable{*remainderOutput}
		} else {
			inputs = currentInputs
		}

		txBytes, txID, remainder, err := s.buildOneTx(inputs, pace, seqInfo, isLastInBatch)
		if err != nil {
			s.log("build tx error: %v", err)
			s.metrics.TxFailed.Add(1)
			break
		}

		// Submit with the consumed UTXO bytes so the node runs full-context
		// (stage-3) validation and returns the real reason on failure —
		// otherwise an invalid non-seq tx is accepted and then silently
		// dropped, which is impossible to diagnose from the spammer side.
		consumed := make([][]byte, len(inputs))
		for i, in := range inputs {
			consumed[i] = in.bytes
		}
		_, err = clnt.SubmitTransactionWithDetail(txBytes, client.WithConsumedUTXOs(consumed))
		if err != nil {
			s.log("submit error: %v", err)
			s.metrics.TxFailed.Add(1)
			s.rotateHost()
			// Retry with next host
			clnt = s.client()
			_, err = clnt.SubmitTransactionWithDetail(txBytes, client.WithConsumedUTXOs(consumed))
			if err != nil {
				s.log("submit retry error: %v", err)
				break
			}
		}

		// Mark consumed inputs as spent
		submittedSlot := txID.Timestamp().Slot
		for _, inp := range inputs {
			s.spentSet[inp.id] = spentEntry{
				TxID:          txID,
				SubmittedSlot: submittedSlot,
			}
		}

		s.metrics.TxSent.Add(1)
		s.nextHost()
		anySent = true

		// Set up remainder for next tx in batch
		remainderOutput = remainder
		if remainderOutput == nil {
			break // no remainder means no balance left
		}
	}

	return anySent
}

// maxFutureJitterTicks caps how far ahead of "now" a jittered timestamp may
// land. The node delays a future-dated tx until the wall clock reaches its
// ledger time (ledger time ≈ wall clock; it only rejects timestamps more than
// ~6 slots ahead), so we keep jitter well inside that window.
const maxFutureJitterTicks = 5 * base.TicksPerSlot

// pickTimestamp chooses the timestamp for a new transaction. The lower bound is
// max(maxInputTs + pace, now): it satisfies the non-sequencer pace invariant and
// is never in the past relative to the clock. On top of that it adds a uniform
// random jitter so timestamps spread across the slot instead of clustering on
// the current clock tick / slot boundary — without jitter every caught-up tx is
// pinned to the same "now" tick, and chained txs step by exactly the pace, so
// transactions bunch up on a fixed grid (notably slot boundaries). The node
// delays a future-dated tx until the clock catches up, so the jitter is safe;
// it is clamped to stay within the node's future-acceptance window.
func (s *Sender) pickTimestamp(inTs base.LedgerTime, pace int) base.LedgerTime {
	lower := inTs.AddTicks(pace)
	now := s.constants.LedgerTimeFromClockTime(time.Now())
	if lower.Before(now) {
		lower = now
	}
	jitter := s.cfg.JitterTicks()
	if jitter <= 0 {
		return lower
	}
	room := int(base.DiffTicks(now.AddTicks(maxFutureJitterTicks), lower))
	if room <= 0 {
		return lower
	}
	if jitter > room {
		jitter = room
	}
	return lower.AddTicks(rand.Intn(jitter + 1))
}

// buildOneTx constructs a single transfer transaction with the raw
// wasm-wallet composer (txbuildercore + the wallet library). No ledger
// singleton: produced outputs are composed via txbuildercore helpers and
// the txID is derived from the signed bytes.
// Returns txBytes, txID, remainder output (for chaining), or error.
func (s *Sender) buildOneTx(inputs []spendable, pace int, seqInfo SequencerInfo, includeTagAlong bool) ([]byte, base.TransactionID, *spendable, error) {
	// Aggregate input total and the maximum input timestamp.
	var inTotal uint64
	inTs := base.NilLedgerTime
	for _, in := range inputs {
		inTotal += in.amount
		inTs = base.MaximumTime(inTs, in.id.Timestamp())
	}

	ts := s.pickTimestamp(inTs, pace)

	tagAlongFee := uint64(0)
	if includeTagAlong {
		tagAlongFee = seqInfo.Fee
	}

	// Decide the transfer amount and remainder so the transaction is always
	// valid and the sender never stalls on an off-by-a-little balance (which
	// breaks the batch loop and caps TPS). Constraints: the target sigLock
	// output must clear the storage-deposit floor, and the remainder must be
	// either zero or also clear the floor (a dust remainder makes the node
	// reject the whole tx). Prefer the configured transfer amount when the
	// leftover is a valid (>= floor) remainder; otherwise spend the whole input
	// into the target with no remainder. Only a balance too small for even one
	// floor-sized output plus the fee is a real "insufficient funds" case.
	if inTotal < tagAlongFee+s.minStorageDeposit {
		return nil, base.TransactionID{}, nil, fmt.Errorf(
			"insufficient balance: have %d, need at least %d (fee %d + storage-deposit floor %d)",
			inTotal, tagAlongFee+s.minStorageDeposit, tagAlongFee, s.minStorageDeposit)
	}

	transferAmount := s.cfg.Global.TransferAmount
	remainderAmount := uint64(0)
	target := s.resolveTarget()
	switch {
	case inTotal >= transferAmount+tagAlongFee+s.minStorageDeposit:
		// Enough for the configured transfer plus a valid (>= floor) remainder to self.
		remainderAmount = inTotal - transferAmount - tagAlongFee
	case inTotal >= 2*s.minStorageDeposit+tagAlongFee:
		// Not enough for the configured transfer, but enough to split into two
		// floor-clearing outputs. Shrink the transfer so a floor-sized remainder stays
		// with the SENDER instead of dumping the whole balance into the target. This is
		// what keeps every account alive and spendable each round (never drained to
		// zero), so it can be topped back up by rebalancing — sustaining TPS with a
		// fixed pool. (Emptying into the target was the ebaab19 coalescence regression.)
		transferAmount = inTotal - tagAlongFee - s.minStorageDeposit
		remainderAmount = s.minStorageDeposit
	default:
		// Too small to split into two floor-clearing outputs (inTotal in
		// [fee+floor, 2*floor+fee)). Churn the whole input back to SELF as one output
		// (no cross-account transfer): still a valid, fee-paying tx that keeps TPS up
		// and the funds with the sender rather than emptying them downstream.
		target = s.holderID
		transferAmount = inTotal - tagAlongFee
	}

	txb := txbuildercore.New(0)

	// Consume inputs and wire the standard unlock pattern:
	// input 0 signs, inputs 1..n reference input 0's lock.
	for i, in := range inputs {
		txb.ConsumeOutput(in.bytes, in.id)
		if i == 0 {
			txb.PutSignatureUnlock(0)
		} else {
			if err := txb.PutUnlockReference(byte(i), txbuildercore.ConstraintIndexLock, 0); err != nil {
				return nil, base.TransactionID{}, nil, err
			}
		}
	}

	// Target output (sigLock to the resolved holder).
	targetOut, err := txbuildercore.NewSigLockOutput(s.lib, transferAmount, target)
	if err != nil {
		return nil, base.TransactionID{}, nil, fmt.Errorf("target output: %w", err)
	}
	txb.ProduceOutput(targetOut.Bytes())

	// Tag-along output (only on last tx in batch)
	if tagAlongFee > 0 {
		taOut, err := txbuildercore.NewTagAlongOutput(s.lib, tagAlongFee, seqInfo.ChainID, s.holderID)
		if err != nil {
			return nil, base.TransactionID{}, nil, fmt.Errorf("tag-along output: %w", err)
		}
		txb.ProduceOutput(taOut.Bytes())
	}

	// Remainder output back to self (produced last). remainderAmount was chosen
	// above to be either zero or >= the storage-deposit floor, so it is never a
	// dust output that the node would reject.
	var remBytes []byte
	var remIdx byte
	if remainderAmount > 0 {
		remOut, err := txbuildercore.NewSigLockOutput(s.lib, remainderAmount, s.holderID)
		if err != nil {
			return nil, base.TransactionID{}, nil, fmt.Errorf("remainder output: %w", err)
		}
		remBytes = remOut.Bytes()
		remIdx = txb.ProduceOutput(remBytes)
	}

	txb.SetTimestamp(ts)
	txb.ComputeInputCommitment()
	txb.SignED25519(s.privateKey)

	txBytes := txb.Bytes()
	txID, err := txbuildercore.TxIDFromBytes(txBytes)
	if err != nil {
		return nil, base.TransactionID{}, nil, fmt.Errorf("txid: %w", err)
	}

	// Build remainder spendable for chaining.
	var remainderOut *spendable
	if remainderAmount > 0 {
		remainderOut = &spendable{
			id:     base.MustNewOutputID(txID, remIdx),
			bytes:  remBytes,
			amount: remainderAmount,
		}
	}

	return txBytes, txID, remainderOut, nil
}

// resolveTarget picks the target holder ID based on strategy.
func (s *Sender) resolveTarget() base.HolderID {
	switch s.cfg.Global.TargetStrategy {
	case StrategyNext:
		nextIdx := (s.index + 1) % len(s.targets)
		return s.targets[nextIdx]
	case StrategyRandom:
		return s.targets[rand.Intn(len(s.targets))]
	case StrategyRebalance:
		return s.pickRebalanceTarget()
	default: // "self"
		return s.holderID
	}
}

// pickRebalanceTarget returns a random sender whose last-known balance is below the
// fleet average (excluding self), so every transfer flows toward the underfunded end
// and the distribution stays even without a separate rebalance pass. Falls back to a
// uniform-random target when balances are not yet known or none is below average.
func (s *Sender) pickRebalanceTarget() base.HolderID {
	if len(s.peerBalances) != len(s.targets) {
		return s.targets[rand.Intn(len(s.targets))]
	}
	var total uint64
	for _, m := range s.peerBalances {
		total += m.LastBalance.Load()
	}
	avg := total / uint64(len(s.peerBalances))

	below := make([]int, 0, len(s.targets))
	for i, m := range s.peerBalances {
		if i == s.index {
			continue // never target self
		}
		if m.LastBalance.Load() < avg {
			below = append(below, i)
		}
	}
	if len(below) == 0 {
		return s.targets[rand.Intn(len(s.targets))]
	}
	return s.targets[below[rand.Intn(len(below))]]
}

// maxFanoutTargets caps the number of funding outputs in one fan-out tx, well under
// the 256-output protocol limit (leaving room for the tag-along and remainder outputs).
const maxFanoutTargets = 200

// tryFanoutFunding, in rebalance mode, lets a rich sender lift many starving accounts
// (below the one-tx send floor) above it in a SINGLE transaction: it produces one
// funding output per starving account — as many as its balance allows — plus a
// remainder that keeps the sender itself active. Returns true if it built and submitted
// such a tx; false (fall through to normal spam) when the sender is not rich enough or
// no accounts are starving. Requires the shared peer-balance view.
func (s *Sender) tryFanoutFunding(available []spendable, availableBalance uint64, currentSlot uint32, seqInfo SequencerInfo, clnt *client.APIClient) bool {
	if len(s.peerBalances) != len(s.targets) {
		return false
	}
	// Throttle: at most one fan-out per RebalanceIntervalSlots, so the previous funding
	// finalizes in the LRB and balances re-read before we decide who is still starving.
	if s.lastFanoutSlot != 0 && currentSlot-s.lastFanoutSlot < uint32(s.cfg.Global.RebalanceIntervalSlots) {
		return false
	}
	// Fund each starving account enough to run a full batch (become fully active);
	// keep the same amount with self so this sender stays active too.
	fundAmount := s.cfg.MinFundingPerSender(seqInfo.Fee, s.minStorageDeposit)
	starvingThreshold := s.cfg.MinBalanceForOneTx(seqInfo.Fee, s.minStorageDeposit)
	selfKeep := fundAmount

	// Not rich enough to fund even one starving account while staying active itself.
	if availableBalance < selfKeep+seqInfo.Fee+fundAmount {
		return false
	}

	// Starving targets (below the one-tx send floor), neediest first.
	starving := make([]int, 0, len(s.peerBalances))
	for i, m := range s.peerBalances {
		if i == s.index {
			continue
		}
		if m.LastBalance.Load() < starvingThreshold {
			starving = append(starving, i)
		}
	}
	if len(starving) == 0 {
		return false
	}
	// Shuffle so concurrent rich senders fund different subsets of the starving set
	// (rather than all piling onto the same neediest few) — maximizes coverage per round.
	rand.Shuffle(len(starving), func(a, b int) { starving[a], starving[b] = starving[b], starving[a] })

	// How many we can fund: bounded by surplus balance, starving count and output cap.
	n := int((availableBalance - selfKeep - seqInfo.Fee) / fundAmount)
	if n > len(starving) {
		n = len(starving)
	}
	if n > maxFanoutTargets {
		n = maxFanoutTargets
	}
	if n <= 0 {
		return false
	}

	txBytes, txID, err := s.buildFanoutTx(available, starving[:n], fundAmount, seqInfo)
	if err != nil {
		s.log("fanout build error: %v", err)
		s.metrics.TxFailed.Add(1)
		return false
	}
	consumed := make([][]byte, len(available))
	for i, in := range available {
		consumed[i] = in.bytes
	}
	if _, err := clnt.SubmitTransactionWithDetail(txBytes, client.WithConsumedUTXOs(consumed)); err != nil {
		s.log("fanout submit error: %v", err)
		s.metrics.TxFailed.Add(1)
		s.rotateHost()
		return false
	}
	submittedSlot := txID.Timestamp().Slot
	for _, in := range available {
		s.spentSet[in.id] = spentEntry{TxID: txID, SubmittedSlot: submittedSlot}
	}
	s.metrics.TxSent.Add(1)
	s.nextHost()
	s.lastFanoutSlot = currentSlot
	if s.verbose {
		s.log("fanout: funded %d starving account(s) with %d each", n, fundAmount)
	}
	return true
}

// buildFanoutTx consumes all of the sender's inputs and produces one fundAmount output
// to each target, a tag-along output, and a remainder back to self. The caller guarantees
// the remainder clears the storage-deposit floor.
func (s *Sender) buildFanoutTx(inputs []spendable, targetIdx []int, fundAmount uint64, seqInfo SequencerInfo) ([]byte, base.TransactionID, error) {
	var inTotal uint64
	inTs := base.NilLedgerTime
	for _, in := range inputs {
		inTotal += in.amount
		inTs = base.MaximumTime(inTs, in.id.Timestamp())
	}
	ts := s.pickTimestamp(inTs, int(s.constants.TransactionPace))

	tagAlongFee := seqInfo.Fee
	remainderAmount := inTotal - fundAmount*uint64(len(targetIdx)) - tagAlongFee

	txb := txbuildercore.New(0)
	for i, in := range inputs {
		txb.ConsumeOutput(in.bytes, in.id)
		if i == 0 {
			txb.PutSignatureUnlock(0)
		} else {
			if err := txb.PutUnlockReference(byte(i), txbuildercore.ConstraintIndexLock, 0); err != nil {
				return nil, base.TransactionID{}, err
			}
		}
	}
	for _, ti := range targetIdx {
		out, err := txbuildercore.NewSigLockOutput(s.lib, fundAmount, s.targets[ti])
		if err != nil {
			return nil, base.TransactionID{}, fmt.Errorf("fanout output: %w", err)
		}
		txb.ProduceOutput(out.Bytes())
	}
	taOut, err := txbuildercore.NewTagAlongOutput(s.lib, tagAlongFee, seqInfo.ChainID, s.holderID)
	if err != nil {
		return nil, base.TransactionID{}, fmt.Errorf("tag-along output: %w", err)
	}
	txb.ProduceOutput(taOut.Bytes())
	remOut, err := txbuildercore.NewSigLockOutput(s.lib, remainderAmount, s.holderID)
	if err != nil {
		return nil, base.TransactionID{}, fmt.Errorf("remainder output: %w", err)
	}
	txb.ProduceOutput(remOut.Bytes())

	txb.SetTimestamp(ts)
	txb.ComputeInputCommitment()
	txb.SignED25519(s.privateKey)
	txBytes := txb.Bytes()
	txID, err := txbuildercore.TxIDFromBytes(txBytes)
	if err != nil {
		return nil, base.TransactionID{}, fmt.Errorf("txid: %w", err)
	}
	return txBytes, txID, nil
}

func (s *Sender) client() *client.APIClient {
	h := s.hosts[s.hostIdx]
	return client.NewWithGoogleDNS(h.URL, h.Timeout)
}

// nextHost advances to the next host according to the configured strategy.
func (s *Sender) nextHost() {
	if len(s.hosts) <= 1 {
		return
	}
	switch s.cfg.Global.HostStrategy {
	case StrategyRandom:
		s.hostIdx = rand.Intn(len(s.hosts))
	default: // "next" — round-robin
		s.hostIdx = (s.hostIdx + 1) % len(s.hosts)
	}
}

// rotateHost advances to a different host on error (always moves forward to avoid the failing host).
func (s *Sender) rotateHost() {
	if len(s.hosts) <= 1 {
		return
	}
	s.hostIdx = (s.hostIdx + 1) % len(s.hosts)
}

func (s *Sender) log(format string, args ...any) {
	if s.logFunc != nil {
		msg := fmt.Sprintf(format, args...)
		s.logFunc("[%s] %s", s.name, msg)
	}
}
