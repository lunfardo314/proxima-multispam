package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/lunfardo314/proxima-multispam/internal/multispam"
	"github.com/lunfardo314/proxima/proxi/glb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func initConflictCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conflict",
		Short: "spam sets of conflicting transactions, one per sequencer",
		Long: `Spam conflicts instead of throughput.

Same rounds and same batch as "run", but the batch is spent as double-spends rather than as
a chain: every transaction of the set consumes the same inputs, and each carries its own
tag-along to a different sequencer. Set size is batch_size, capped at the number of
sequencers so no two members share one; at batch_size 1 this is exactly "run".

A node attaches a non-sequencer transaction only if it carries an output for its own
sequencer, so every member of the set lands in exactly one sequencer's backlog. Only one can
be consolidated, which leaves the other sequencers having to revert their own state.

The set is spaced by the ledger transaction pace: its members share a holder, and a node
drops a transaction whose timestamp is within the pace of another from the same holder
before it is ever gossiped.`,
		Args: cobra.NoArgs,
		Run:  runConflictCmd,
	}
	cmd.Flags().IntP("senders", "n", 0, "number of senders to use (default: all)")
	cmd.Flags().Int("fanout", 0, "transactions per conflict set, overriding batch_size (capped at the number of sequencers)")
	cmd.Flags().Duration("max-duration", 0, "stop after duration (e.g. 10m, 1h)")
	cmd.Flags().Int64("max-transactions", 0, "stop after total transaction count")
	return cmd
}

func runConflictCmd(cmd *cobra.Command, _ []string) {
	configFile := viper.GetString("multispam-config")
	cfg, err := multispam.LoadConfig(configFile)
	glb.AssertNoError(err)

	firstHost := cfg.APIHosts[0]
	viper.Set("api.endpoint", firstHost.URL)
	if firstHost.Timeout > 0 {
		viper.Set("api.timeout_sec", int(firstHost.Timeout.Seconds()))
	}

	lib := glb.GetTxLibrary()
	constants := glb.GetLedgerConstants()

	numSenders, _ := cmd.Flags().GetInt("senders")
	fanout, _ := cmd.Flags().GetInt("fanout")
	maxDuration, _ := cmd.Flags().GetDuration("max-duration")
	maxTx, _ := cmd.Flags().GetInt64("max-transactions")

	coord, err := multispam.NewCoordinator(multispam.CoordinatorParams{
		Config:          cfg,
		NumSenders:      numSenders,
		Library:         lib,
		Constants:       constants,
		MaxDuration:     maxDuration,
		MaxTransactions: maxTx,
		Verbose:         glb.IsVerbose(),
		Conflict:        true,
		ConflictFanout:  fanout,
		LogFunc: func(format string, args ...any) {
			glb.Infof(format, args...)
		},
	})
	glb.AssertNoError(err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		glb.Infof("shutting down...")
		cancel()
		<-sigCh
		os.Exit(1)
	}()

	if maxDuration > 0 {
		glb.Infof("max duration: %v", maxDuration)
	}
	if maxTx > 0 {
		glb.Infof("max transactions: %d", maxTx)
	}

	err = coord.Run(ctx)
	glb.AssertNoError(err)
}
