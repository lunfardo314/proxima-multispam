package main

import (
	"fmt"

	"github.com/lunfardo314/proxima-multispam/internal/multispam"
	"github.com/lunfardo314/proxima/proxi/glb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func initInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "display sender account balances and funding requirements",
		Args:  cobra.NoArgs,
		Run:   runInfoCmd,
	}
}

func runInfoCmd(_ *cobra.Command, _ []string) {
	configFile := viper.GetString("multispam-config")
	cfg, err := multispam.LoadConfig(configFile)
	glb.AssertNoError(err)

	// Use first API host from multispam config so wallet config is not required
	firstHost := cfg.APIHosts[0]
	viper.Set("api.endpoint", firstHost.URL)
	if firstHost.Timeout > 0 {
		viper.Set("api.timeout_sec", int(firstHost.Timeout.Seconds()))
	}

	clnt := glb.GetClient()

	// Discover sequencer fees so the minimum reflects the real tag-along fee.
	// Use the largest minimum-fee so the figure holds for any sequencer a
	// sender might pick. Fall back to 1 if discovery fails.
	tagAlongFee := uint64(1)
	seqCount := 0
	seqReg := multispam.NewSequencerRegistry()
	if err := seqReg.Refresh(clnt); err != nil {
		fmt.Printf("warning: could not discover sequencers (%v); assuming tag-along fee = %d\n", err, tagAlongFee)
	} else if f, n := seqReg.MaxFee(); n > 0 {
		if f > 0 {
			tagAlongFee = f
		}
		seqCount = n
	}

	// Storage-deposit floor for the sigLock outputs each sender produces. A
	// produced sigLock output (target or remainder) below this makes the whole
	// transaction invalid ("storage deposit not met"), so it is part of the
	// minimum funding, not an afterthought.
	minStorageDeposit, err := multispam.MinStorageDepositSigLock(glb.GetTxLibrary(), clnt)
	glb.AssertNoError(err)

	// Per-sender minimum to run one full batch round without producing a dust
	// (sub-storage-deposit) output. Batch-size and storage-deposit dependent.
	minPerSender := cfg.MinFundingPerSender(tagAlongFee, minStorageDeposit)

	fmt.Printf("%-12s %-20s %8s %18s  %s\n", "Name", "Holder ID", "Outputs", "Balance", "Status")
	fmt.Printf("%-12s %-20s %8s %18s  %s\n", "----", "---------", "-------", "-------", "------")

	var totalBalance uint64
	var queried, fundedCount, underfundedCount int
	for _, s := range cfg.Senders {
		addr, err := multispam.SenderAddress(s.KeyFile)
		if err != nil {
			fmt.Printf("%-12s error: %v\n", s.Name, err)
			continue
		}
		holderID, _ := multispam.SenderHolderID(s.KeyFile)

		outs, _, balance, err := clnt.GetTransferableOutputs(addr, 256)
		if err != nil {
			fmt.Printf("%-12s %-20s error: %v\n", s.Name, holderID[:16]+"...", err)
			continue
		}

		status := "ok"
		if balance >= minPerSender {
			fundedCount++
		} else {
			underfundedCount++
			status = fmt.Sprintf("UNDERFUNDED (needs %d more)", minPerSender-balance)
		}
		fmt.Printf("%-12s %-20s %8d %18d  %s\n", s.Name, holderID[:16]+"...", len(outs), balance, status)
		totalBalance += balance
		queried++
	}
	fmt.Printf("%-12s %-20s %8s %18d\n", "TOTAL", "", "", totalBalance)

	// General summary
	numSenders := len(cfg.Senders)
	var avgBalance uint64
	if queried > 0 {
		avgBalance = totalBalance / uint64(queried)
	}
	minTotal := minPerSender * uint64(numSenders)

	fmt.Println()
	fmt.Println("Summary")
	fmt.Println("-------")
	fmt.Printf("  senders configured:          %d\n", numSenders)
	fmt.Printf("  total balance:               %d\n", totalBalance)
	fmt.Printf("  average balance:             %d\n", avgBalance)
	if seqCount > 0 {
		fmt.Printf("  tag-along fee (max of %d):    %d\n", seqCount, tagAlongFee)
	} else {
		fmt.Printf("  tag-along fee (assumed):     %d\n", tagAlongFee)
	}
	fmt.Printf("  transfer amount:             %d\n", cfg.Global.TransferAmount)
	fmt.Printf("  batch size:                  %d\n", cfg.Global.BatchSize)
	fmt.Printf("  sigLock storage deposit:     %d  (min per produced output)\n", minStorageDeposit)
	fmt.Printf("  min funding per sender:      %d  (%d x transfer + fee + storage deposit)\n",
		minPerSender, cfg.Global.BatchSize)
	fmt.Printf("  min total to fund all:       %d  (%d senders x %d)\n", minTotal, numSenders, minPerSender)
	fmt.Printf("  funded enough:               %d\n", fundedCount)
	fmt.Printf("  need additional funding:     %d\n", underfundedCount)
	if underfundedCount > 0 {
		fmt.Printf("\n  WARNING: %d sender(s) underfunded — their transactions will be rejected by the node\n", underfundedCount)
		fmt.Printf("           (dust remainder below the %d storage-deposit floor). Fund them before running.\n", minStorageDeposit)
	}
	// Each transfer produces a sigLock target output carrying exactly
	// transfer_amount. If that is below the storage-deposit floor, every target
	// output is dust and the node rejects every spam tx no matter how well the
	// senders are funded — so flag it independently of the per-sender numbers.
	if cfg.Global.TransferAmount < minStorageDeposit {
		fmt.Printf("\n  WARNING: transfer_amount %d is below the sigLock storage-deposit floor %d.\n", cfg.Global.TransferAmount, minStorageDeposit)
		fmt.Printf("           Every target output would be dust and rejected by the node, regardless of\n")
		fmt.Printf("           funding. Raise transfer_amount to at least %d.\n", minStorageDeposit)
	}
}
