package main

import (
	"github.com/lunfardo314/proxima/proxi/glb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "multispam [<subcommand>]",
		Short: "multi-sender spammer for Proxima TPS testing",
		Args:  cobra.NoArgs,
	}

	rootCmd.PersistentFlags().StringP("config", "c", "", "proxi config profile name (for fund/init only)")
	err := viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))
	glb.AssertNoError(err)

	rootCmd.PersistentFlags().String("multispam-config", "multispam.yaml", "multispam config file")
	err = viper.BindPFlag("multispam-config", rootCmd.PersistentFlags().Lookup("multispam-config"))
	glb.AssertNoError(err)

	rootCmd.InitDefaultHelpCmd()
	rootCmd.AddCommand(
		initInitCmd(),
		initInfoCmd(),
		initFundCmd(),
		initWithdrawCmd(),
		initRunCmd(),
		initConflictCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		glb.Fatalf("%v", err)
	}
}
