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
	spentSet  map[base.OutputID]spentEntry
	metrics   *SenderMetrics
	logFunc   func(format string, args ...any)
	verbose   bool

	// minStorageDeposit is the sigLock storage-deposit floor (computed once,
	// wallet-side). A produced sigLock output below it makes the tx invalid.
	minStorageDeposit uint64

	// conflict mode: every round spends the batch as a set of mutually conflicting
	// transactions instead of a chain. conflictFanout overrides batch_size as the size of
	// the set; 0 means take batch_size.
	conflict       bool
	conflictFanout int
}

// SenderMetrics holds per-sender counters, read atomically by the coordinator.
type SenderMetrics struct {
	TxSent       atomic.Int64
	TxFailed     atomic.Int64
	LastBalance  atomic.Uint64
	ConflictSets atomic.Int64
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

	// Conflict and ConflictFanout select and size conflict mode (see Sender).
	Conflict       bool
	ConflictFanout int
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
		conflict:          par.Conflict,
		conflictFanout:    par.ConflictFanout,
	}
}

func (s *Sender) Metrics() *SenderMetrics { return s.metrics }
func (s *Sender) Name() string            { return s.name }

// Run is the main sender loop. Blocks until context is cancelled.
func (s *Sender) Run(ctx context.Context) {
	pace := int(s.constants.TransactionPace)
	mindRateControl := s.cfg.IsMindRateControl()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		sent, waitTicks := s.doRound(pace)
		if sent && waitTicks == 0 && !mindRateControl {
			continue
		}
		if waitTicks <= 0 {
			// nothing to spend, or rate control asked for the plain pace
			waitTicks = pace
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(waitTicks) * s.constants.TickDuration):
		}
	}
}

// doRound performs one iteration: query outputs, classify, build and submit.
// Returns whether anything was submitted, and how many ledger ticks to wait before the next
// round. The wait is zero unless the round itself dictates one — a conflict set reserves a
// stretch of this holder's timeline and the next round must start after it.
func (s *Sender) doRound(pace int) (bool, int) {
	clnt := s.client()

	// Step 1: Query LRB outputs
	outs, _, totalBalance, err := clnt.GetTransferableOutputs(s.account, 256)
	if err != nil {
		s.log("error fetching outputs: %v", err)
		s.rotateHost()
		return false, 0
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
		return false, 0
	}

	// Step 3: Get sequencer(s) for tag-along. A chained batch pays a single fee, on its last
	// transaction; a conflict set pays one per member, each to a different sequencer.
	seqs := s.pickSequencers()
	if len(seqs) == 0 {
		s.log("no sequencers available")
		return false, 0
	}

	// Step 4: Check minimum balance. A sender with funds below the floor for a
	// single valid transfer cannot transact without producing a dust remainder
	// (which the node silently rejects). This is expected while waiting for
	// funding to arrive, so only surface it under -v to avoid noise. Senders
	// with zero spendable outputs were already handled above and stay quiet.
	fee := maxFee(seqs)
	minForOneTx := s.cfg.MinBalanceForOneTx(fee, s.minStorageDeposit)
	if availableBalance < minForOneTx {
		if s.verbose {
			s.log("UNDERFUNDED: spendable %d < minimum %d (transfer %d + fee %d + storage deposit %d) — fund this sender",
				availableBalance, minForOneTx, s.cfg.Global.TransferAmount, fee, s.minStorageDeposit)
		}
		return false, 0
	}

	// Step 5: Build and submit
	if s.conflict {
		return s.buildAndSubmitConflictSet(available, pace, seqs, clnt)
	}
	return s.buildAndSubmitBatch(available, pace, seqs[0], clnt), 0
}

// pickSequencers returns the sequencers to tag along with this round: one for a chained batch,
// one per member of a conflict set.
func (s *Sender) pickSequencers() []SequencerInfo {
	if s.conflict {
		return s.seqPicker.Distinct(s.setSize())
	}
	if seqInfo, ok := s.seqPicker.Next(); ok {
		return []SequencerInfo{seqInfo}
	}
	return nil
}

// setSize is the requested number of transactions per conflict set: batch_size, a conflict set
// being a batch spent as double-spends rather than as a chain, unless --fanout overrides it.
// The picker caps it at the number of sequencers.
func (s *Sender) setSize() int {
	if s.conflictFanout > 0 {
		return s.conflictFanout
	}
	return s.cfg.Global.BatchSize
}

func maxFee(seqs []SequencerInfo) (ret uint64) {
	for _, sq := range seqs {
		if sq.Fee > ret {
			ret = sq.Fee
		}
	}
	return
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

		ts := s.pickTimestamp(inputTimestamp(inputs), pace)
		txBytes, txID, remainder, err := s.buildOneTx(inputs, ts, seqInfo, isLastInBatch)
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

// buildAndSubmitConflictSet spends the batch as a set of double-spends rather than as a chain.
// Every member consumes the same inputs — the same ones a batch would start from — and each
// carries its own tag-along, to a different sequencer. Returns whether anything was submitted
// and how many ledger ticks the set reserves on this holder's timeline.
//
// A node attaches an unsolicited non-sequencer transaction only if it carries an output for
// its own sequencer, so each member lands in exactly one sequencer's backlog and every one of
// them sees a tag-along it wants. Only one member can ever be consolidated, so the sequencers
// holding the others have to revert their own state to converge with the winner. A sequencer
// unwilling to revert stays on a lineage it cannot bring its peers onto, which is the
// behaviour this mode exists to provoke.
//
// The members are spaced by the ledger's non-sequencer transaction pace. They share a holder
// by construction — a UTXO is spendable only by its owner, and a transaction carries a single
// signature — and a node drops a transaction whose timestamp falls within the pace of another
// from the same holder. That check runs before the transaction is persisted or gossiped, so a
// tighter set would collapse to one transaction and produce no conflict at all.
//
// A set of one reserves nothing and is exactly the batch of one.
func (s *Sender) buildAndSubmitConflictSet(available []spendable, pace int, seqs []SequencerInfo, clnt *client.APIClient) (bool, int) {
	tsSet := conflictTimestamps(s.pickTimestamp(inputTimestamp(available), pace), len(seqs), pace)

	consumed := make([][]byte, len(available))
	for i, in := range available {
		consumed[i] = in.bytes
	}

	sent := 0
	for i, seqInfo := range seqs {
		txBytes, txID, _, err := s.buildOneTx(available, tsSet[i], seqInfo, true)
		if err != nil {
			s.log("conflict build error: %v", err)
			s.metrics.TxFailed.Add(1)
			break
		}
		if _, err = clnt.SubmitTransactionWithDetail(txBytes, client.WithConsumedUTXOs(consumed)); err != nil {
			s.log("conflict submit error: %v", err)
			s.metrics.TxFailed.Add(1)
			s.rotateHost()
			clnt = s.client()
			// One unreachable host must not cost the whole set — carry on with the next member
			// rather than abandoning the remaining sequencers.
			if _, err = clnt.SubmitTransactionWithDetail(txBytes, client.WithConsumedUTXOs(consumed)); err != nil {
				s.log("conflict submit retry error: %v", err)
				continue
			}
		}
		// Whichever member wins, the inputs are gone. Recording one spender is enough: if the
		// whole set is lost, the finality timeout reclaims the outputs either way.
		submittedSlot := txID.Timestamp().Slot
		for _, in := range available {
			s.spentSet[in.id] = spentEntry{TxID: txID, SubmittedSlot: submittedSlot}
		}
		s.metrics.TxSent.Add(1)
		sent++
		s.nextHost()
		clnt = s.client()
	}
	if sent == 0 {
		return false, 0
	}
	s.metrics.ConflictSets.Add(1)
	if len(tsSet) == 1 {
		return true, 0
	}

	// Wait out the stretch of this holder's timeline the set occupies, plus one pace, so the
	// next set cannot land inside any member's pace window.
	now := s.constants.LedgerTimeFromClockTime(time.Now())
	return true, int(base.DiffTicks(tsSet[len(tsSet)-1], now)) + pace
}

// conflictTimestamps spaces the members of a conflict set exactly one transaction pace apart,
// which is the tightest spacing a node will accept from a single holder.
func conflictTimestamps(first base.LedgerTime, n, pace int) []base.LedgerTime {
	ret := make([]base.LedgerTime, n)
	for i := range ret {
		ret[i] = first.AddTicks(i * pace)
	}
	return ret
}

// maxFutureJitterTicks caps how far ahead of "now" a jittered timestamp may
// land. The node delays a future-dated tx until the wall clock reaches its
// ledger time (ledger time ≈ wall clock; it only rejects timestamps more than
// ~6 slots ahead), so we keep jitter well inside that window.
const maxFutureJitterTicks = 5 * base.TicksPerSlot

// inputTimestamp is the latest timestamp among the consumed outputs — the point the
// transaction pace is measured from.
func inputTimestamp(inputs []spendable) base.LedgerTime {
	ret := base.NilLedgerTime
	for _, in := range inputs {
		ret = base.MaximumTime(ret, in.id.Timestamp())
	}
	return ret
}

// paceLowerBound is the earliest timestamp a new transaction may carry: a pace after the
// latest input, and never behind the clock.
func (s *Sender) paceLowerBound(inTs base.LedgerTime, pace int) base.LedgerTime {
	lower := inTs.AddTicks(pace)
	if now := s.constants.LedgerTimeFromClockTime(time.Now()); lower.Before(now) {
		lower = now
	}
	return lower
}

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
	lower := s.paceLowerBound(inTs, pace)
	now := s.constants.LedgerTimeFromClockTime(time.Now())
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
func (s *Sender) buildOneTx(inputs []spendable, ts base.LedgerTime, seqInfo SequencerInfo, includeTagAlong bool) ([]byte, base.TransactionID, *spendable, error) {
	var inTotal uint64
	for _, in := range inputs {
		inTotal += in.amount
	}

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
	if inTotal >= transferAmount+tagAlongFee+s.minStorageDeposit {
		// Configured transfer leaves a remainder that still clears the floor.
		remainderAmount = inTotal - transferAmount - tagAlongFee
	} else {
		// Not enough headroom for the configured transfer plus a valid
		// remainder — spend the whole input into the target, no remainder.
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
	targetOut, err := txbuildercore.NewSigLockOutput(s.lib, transferAmount, s.resolveTarget())
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
	default: // "self"
		return s.holderID
	}
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
