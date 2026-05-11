package cmd

import (
	"github.com/keyorixhq/dashdiag/internal/tips"
	"github.com/spf13/cobra"
)

var tipsCmd = &cobra.Command{
	Use:   "tips",
	Short: "Show all DashDiag tips and shortcuts",
	RunE: func(cmd *cobra.Command, args []string) error {
		tips.PrintAllTips()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(tipsCmd)
}
