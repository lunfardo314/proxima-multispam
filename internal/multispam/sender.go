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
	}
}

func (s *Sender) Metrics() *SenderMetrics { return s.metrics }
func (s *Sender) Name() string            { return s.name }

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

	// Step 4: Check minimum balance
	if availableBalance < s.cfg.MinBalanceToParticipate(seqInfo.Fee) {
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

		// Submit
		err = clnt.SubmitTransaction(txBytes)
		if err != nil {
			s.log("submit error: %v", err)
			s.metrics.TxFailed.Add(1)
			s.rotateHost()
			// Retry with next host
			clnt = s.client()
			err = clnt.SubmitTransaction(txBytes)
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

	// Timestamp: max input ts + pace, but never before "now". Both
	// branches keep the pace invariant, so the node accepts the tx.
	ts := inTs.AddTicks(pace)
	now := s.constants.LedgerTimeFromClockTime(time.Now())
	if ts.Before(now) {
		ts = now
	}

	transferAmount := s.cfg.Global.TransferAmount
	tagAlongFee := uint64(0)
	if includeTagAlong {
		tagAlongFee = seqInfo.Fee
	}

	if inTotal < transferAmount+tagAlongFee {
		return nil, base.TransactionID{}, nil, fmt.Errorf("insufficient balance: have %d, need %d", inTotal, transferAmount+tagAlongFee)
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

	// Remainder output back to self (produced last).
	remainderAmount := inTotal - transferAmount - tagAlongFee
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
