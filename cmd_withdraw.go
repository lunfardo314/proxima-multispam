package main

import (
	"fmt"
	"time"

	"github.com/lunfardo314/proxima-multispam/internal/multispam"
	"github.com/lunfardo314/proxima/ledger/base"
	"github.com/lunfardo314/proxima/ledger/txbuildercore"
	"github.com/lunfardo314/proxima/proxi/glb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Max UTXOs consumed per withdrawal tx. A tx caps at 256 elements; withdraw
// produces two outputs (target + tag-along), so consume at most 254 inputs and
// leave room. A sender holding more than this keeps a small remainder that a
// second `withdraw` run sweeps.
const maxInputsPerWithdrawTx = 254

func initWithdrawCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "withdraw",
		Short: "sweep all sender balances back into the wallet",
		Long: "For each sender with a non-zero balance, consume all its UTXOs and " +
			"send the whole balance to the current wallet as a single output. " +
			"Transactions are posted but not waited on; run `info` afterwards to " +
			"confirm balances reached zero.",
		Args: cobra.NoArgs,
		Run:  runWithdrawCmd,
	}
	cmd.Flags().StringSlice("senders", nil, "withdraw only from named senders (comma-separated or repeated, default: all)")
	return cmd
}

func runWithdrawCmd(cmd *cobra.Command, _ []string) {
	glb.ReadInConfig()

	configFile := viper.GetString("multispam-config")
	cfg, err := multispam.LoadConfig(configFile)
	glb.AssertNoError(err)

	senderNames, _ := cmd.Flags().GetStringSlice("senders")
	senders := cfg.Senders
	if len(senderNames) > 0 {
		senders = filterSenders(cfg.Senders, senderNames)
	}

	// Wallet state (singleton-free): the sweep target is the current wallet.
	walletData := glb.GetWalletData()
	clnt := glb.GetClient()
	lib := glb.GetTxLibrary()
	constants := glb.GetLedgerConstants()
	walletHolderID := base.HolderIDFromED25519PrivateKey(walletData.PrivateKey)

	tagAlongSeqID := glb.GetTagAlongSequencerID()
	glb.Assertf(tagAlongSeqID != nil, "tag-along sequencer not specified (set tag_along.sequencer_id)")
	tagAlongFee := glb.GetTagAlongFee()
	if tagAlongFee == 0 {
		tagAlongFee = 1
	}

	// Storage-deposit floor: the single swept output is a sigLock output and
	// must clear this floor, else the node rejects the tx.
	minStorageDeposit, err := multispam.MinStorageDepositSigLock(lib, clnt)
	glb.AssertNoError(err)

	pace := int(constants.TransactionPace)

	glb.Infof("withdrawing balances of %d sender(s) into wallet %s", len(senders), walletHolderID.String())

	var swept, skipped, failed int
	var totalWithdrawn uint64
	for _, s := range senders {
		addr, err := multispam.SenderAddress(s.KeyFile)
		if err != nil {
			glb.Infof("  %-12s error resolving address: %v", s.Name, err)
			failed++
			continue
		}

		outs, _, balance, err := clnt.GetTransferableOutputs(addr, maxInputsPerWithdrawTx)
		if err != nil {
			glb.Infof("  %-12s error fetching outputs: %v", s.Name, err)
			failed++
			continue
		}

		if len(outs) == 0 || balance == 0 {
			glb.Infof("  %-12s zero balance — skipped", s.Name)
			skipped++
			continue
		}

		// The single swept output carries balance - tagAlongFee and must clear
		// the storage-deposit floor. Anything smaller can't be swept as one
		// valid output, so skip it rather than post a tx the node rejects.
		if balance <= tagAlongFee || balance-tagAlongFee < minStorageDeposit {
			glb.Infof("  %-12s balance %d too small to withdraw (needs > fee %d + storage deposit %d) — skipped",
				s.Name, balance, tagAlongFee, minStorageDeposit)
			skipped++
			continue
		}
		amount := balance - tagAlongFee

		privKey, err := multispam.LoadSenderKey(s.KeyFile)
		if err != nil {
			glb.Infof("  %-12s error loading key: %v", s.Name, err)
			failed++
			continue
		}

		// Build a single tx consuming every UTXO into one wallet output.
		txb := txbuildercore.New(0)
		maxInputTs := base.NilLedgerTime
		consumedUTXOBytes := make([][]byte, len(outs))
		for i, o := range outs {
			txb.ConsumeOutput(o.Output.Bytes(), o.ID)
			consumedUTXOBytes[i] = o.Output.Bytes()
			maxInputTs = base.MaximumTime(maxInputTs, o.ID.Timestamp())
		}
		// All inputs share the sender's sigLock: input 0 signs, the rest
		// reference it.
		err = txb.PutStandardInputUnlocks(len(outs))
		glb.AssertNoError(err)

		// The swept output goes to the wallet as a single sigLock output.
		sweptOut, err := txbuildercore.NewSigLockOutput(lib, amount, walletHolderID)
		glb.AssertNoError(err)
		txb.ProduceOutput(sweptOut.Bytes())

		// Tag-along output pays the sequencer; sender is the tag-along holder.
		senderHolderID := base.HolderID(addr)
		tagAlongOut, err := txbuildercore.NewTagAlongOutput(lib, tagAlongFee, *tagAlongSeqID, senderHolderID)
		glb.AssertNoError(err)
		txb.ProduceOutput(tagAlongOut.Bytes())

		// Timestamp: respect the non-sequencer pace over the newest input and
		// never land in the past relative to the clock.
		ts := maxInputTs.AddTicks(pace)
		now := constants.LedgerTimeFromClockTime(time.Now())
		if ts.Before(now) {
			ts = now
		}
		txb.SetTimestamp(ts)
		txb.ComputeInputCommitment()
		txb.SignED25519(privKey)

		txBytes := txb.Bytes()
		txid, err := txbuildercore.TxIDFromBytes(txBytes)
		glb.AssertNoError(err)

		glb.Infof("  %-12s %3d UTXOs, balance %d -> withdrawing %d (fee %d), tx %s",
			s.Name, len(outs), balance, amount, tagAlongFee, txid.StringShort())

		// Submit with the consumed UTXOs so the node runs full-context
		// validation synchronously and returns the real reason on rejection.
		// We do not wait for confirmation.
		if err := glb.SubmitAndDisplay(txBytes, consumedUTXOBytes...); err != nil {
			glb.Infof("  %-12s submit failed: %v", s.Name, err)
			failed++
			continue
		}

		swept++
		totalWithdrawn += amount
	}

	glb.Infof("withdraw submitted: %d swept, %d skipped, %d failed, %d total tokens (not yet confirmed)",
		swept, skipped, failed, totalWithdrawn)
	fmt.Println("run `multispam info` after finality to confirm all balances reached zero")
}
