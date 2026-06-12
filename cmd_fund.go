package main

import (
	"fmt"
	"time"

	"github.com/lunfardo314/proxima-multispam/internal/multispam"
	"github.com/lunfardo314/proxima/api"
	"github.com/lunfardo314/proxima/api/client"
	"github.com/lunfardo314/proxima/ledger/base"
	"github.com/lunfardo314/proxima/ledger/txbuildercore"
	"github.com/lunfardo314/proxima/proxi/glb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Max targets per transaction: 256 outputs minus tag-along (1) minus remainder (1) = 254
const maxTargetsPerTx = 254

func initFundCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fund",
		Short: "fund sender accounts from wallet",
		Args:  cobra.NoArgs,
		Run:   runFundCmd,
	}
	cmd.Flags().Uint64("amount", 0, "amount of tokens to send to each sender (required)")
	_ = cmd.MarkFlagRequired("amount")
	cmd.Flags().StringSlice("senders", nil, "fund only named senders (comma-separated or repeated, default: all)")
	return cmd
}

func runFundCmd(cmd *cobra.Command, _ []string) {
	glb.ReadInConfig()

	configFile := viper.GetString("multispam-config")
	cfg, err := multispam.LoadConfig(configFile)
	glb.AssertNoError(err)

	amount, _ := cmd.Flags().GetUint64("amount")
	if amount == 0 {
		glb.Fatalf("--amount must be > 0")
	}

	senderNames, _ := cmd.Flags().GetStringSlice("senders")

	// Resolve target senders
	senders := cfg.Senders
	if len(senderNames) > 0 {
		senders = filterSenders(cfg.Senders, senderNames)
	}

	// Wasm-wallet state (no ledger.L() singleton).
	walletData := glb.GetWalletData()
	clnt := glb.GetClient()
	lib := glb.GetTxLibrary()
	walletHolderID := base.HolderIDFromED25519PrivateKey(walletData.PrivateKey)

	tagAlongSeqID := glb.GetTagAlongSequencerID()
	glb.Assertf(tagAlongSeqID != nil, "tag-along sequencer not specified (set tag_along.sequencer_id)")
	tagAlongFee := glb.GetTagAlongFee()
	if tagAlongFee == 0 {
		tagAlongFee = 1
	}

	// Resolve sender holder IDs
	type target struct {
		name     string
		holderID base.HolderID
	}
	targets := make([]target, len(senders))
	for i, s := range senders {
		addr, err := multispam.SenderAddress(s.KeyFile)
		glb.AssertNoError(err)
		targets[i] = target{name: s.Name, holderID: base.HolderID(addr)}
	}

	glb.Infof("funding %d senders with %d tokens each from wallet", len(targets), amount)

	// Split into batches that fit within max outputs per tx
	for batchStart := 0; batchStart < len(targets); batchStart += maxTargetsPerTx {
		batchEnd := batchStart + maxTargetsPerTx
		if batchEnd > len(targets) {
			batchEnd = len(targets)
		}
		batch := targets[batchStart:batchEnd]

		totalNeeded := amount*uint64(len(batch)) + tagAlongFee
		res, err := clnt.GetOutputsForControllerID(walletData.Account.ControllerID().Bytes(), client.GetOutputsParams{
			LockType:  api.GetOutputsLockTypeSigLock,
			Chained:   client.NonChainedOnly(),
			SortBy:    api.GetOutputsSortByAmount,
			SortOrder: api.GetOutputsSortOrderDesc,
			ForAmount: totalNeeded,
		})
		glb.AssertNoError(err)
		glb.Assertf(res.AvailableAmount >= totalNeeded, "not enough tokens: have %d, need %d", res.AvailableAmount, totalNeeded)
		walletOutputs := res.Outputs

		// Build multi-output transaction with the wasm-wallet composer.
		txb := txbuildercore.New(0)

		var inTotal uint64
		for _, o := range walletOutputs {
			txb.ConsumeOutput(o.Output.Bytes(), o.ID)
			inTotal += o.Output.TokenBalance()
		}
		err = txb.PutStandardInputUnlocks(len(walletOutputs))
		glb.AssertNoError(err)

		// Produce one sigLock output per target
		for _, t := range batch {
			out, err := txbuildercore.NewSigLockOutput(lib, amount, t.holderID)
			glb.AssertNoError(err)
			txb.ProduceOutput(out.Bytes())
		}

		// Produce tag-along output
		tagAlongOut, err := txbuildercore.NewTagAlongOutput(lib, tagAlongFee, *tagAlongSeqID, walletHolderID)
		glb.AssertNoError(err)
		txb.ProduceOutput(tagAlongOut.Bytes())

		// Produce remainder if needed
		spent := amount*uint64(len(batch)) + tagAlongFee
		if inTotal > spent {
			remainderOut, err := txbuildercore.NewSigLockOutput(lib, inTotal-spent, walletHolderID)
			glb.AssertNoError(err)
			txb.ProduceOutput(remainderOut.Bytes())
		}

		// Finalise: timestamp (node's current ledger slot), commitment, signature.
		txb.SetTimestamp(base.T(glb.GetLedgerTimeNow().Slot, 10))
		txb.ComputeInputCommitment()
		txb.SignED25519(walletData.PrivateKey)

		txBytes := txb.Bytes()
		txid, err := txbuildercore.TxIDFromBytes(txBytes)
		glb.AssertNoError(err)

		// Submit with the consumed UTXOs so the node runs full-context
		// validation synchronously and rejects (e.g. on a storage-deposit
		// violation) instead of accepting and silently dropping the tx
		// during async attachment. On rejection SubmitAndDisplay prints
		// the node error plus the full rendering of the invalid tx.
		consumedUTXOBytes := make([][]byte, len(walletOutputs))
		for i, o := range walletOutputs {
			consumedUTXOBytes[i] = o.Output.Bytes()
		}
		err = glb.SubmitAndDisplay(txBytes, consumedUTXOBytes...)
		glb.AssertNoError(err)

		for _, t := range batch {
			glb.Infof("  %s: %d tokens", t.name, amount)
		}
		glb.Infof("submitted tx %s (%d targets, %d total tokens)", txid.StringShort(), len(batch), amount*uint64(len(batch)))

		included := glb.TrackTxInclusion(txid, time.Second)
		if !included {
			glb.Fatalf("transaction %s not included, aborting", txid.StringShort())
		}
		fmt.Println()
	}

	glb.Infof("funding complete")
}

func filterSenders(all []multispam.SenderConfig, names []string) []multispam.SenderConfig {
	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}
	var result []multispam.SenderConfig
	for _, s := range all {
		if nameSet[s.Name] {
			result = append(result, s)
			delete(nameSet, s.Name)
		}
	}
	for n := range nameSet {
		glb.Fatalf("sender '%s' not found in config", n)
	}
	return result
}
