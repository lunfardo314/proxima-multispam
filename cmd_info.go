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
		Short: "display sender account balances",
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

	// Discover sequencer fees so the participation-minimum reflects the real
	// tag-along fee. Use the largest minimum-fee so the figure holds for any
	// sequencer a sender might pick. Fall back to 1 if discovery fails.
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

	minPerSender := cfg.MinBalanceToParticipate(tagAlongFee)

	fmt.Printf("%-12s %-20s %8s %15s\n", "Name", "Holder ID", "Outputs", "Balance")
	fmt.Printf("%-12s %-20s %8s %15s\n", "----", "---------", "-------", "-------")

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

		flag := ""
		if balance >= minPerSender {
			fundedCount++
		} else {
			underfundedCount++
			flag = " (underfunded)"
		}
		fmt.Printf("%-12s %-20s %8d %15d%s\n", s.Name, holderID[:16]+"...", len(outs), balance, flag)
		totalBalance += balance
		queried++
	}
	fmt.Printf("%-12s %-20s %8s %15d\n", "TOTAL", "", "", totalBalance)

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
	fmt.Printf("  senders configured:         %d\n", numSenders)
	fmt.Printf("  total balance:              %d\n", totalBalance)
	fmt.Printf("  average balance:            %d\n", avgBalance)
	if seqCount > 0 {
		fmt.Printf("  tag-along fee (max of %d):   %d\n", seqCount, tagAlongFee)
	} else {
		fmt.Printf("  tag-along fee (assumed):    %d\n", tagAlongFee)
	}
	fmt.Printf("  transfer amount:            %d\n", cfg.Global.TransferAmount)
	fmt.Printf("  batch size:                 %d (max spend/round %d)\n", cfg.Global.BatchSize, cfg.PerRoundMaxSpend(tagAlongFee))
	fmt.Printf("  min per sender to run:      %d  (2 x transfer + tag-along fee)\n", minPerSender)
	fmt.Printf("  min total to fund all:      %d  (%d senders x %d)\n", minTotal, numSenders, minPerSender)
	fmt.Printf("  funded enough:              %d\n", fundedCount)
	fmt.Printf("  need additional funding:    %d\n", underfundedCount)
}
