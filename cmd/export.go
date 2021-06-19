package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(exportCmd)
}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Exports certificates and accounts",
	Long: `Exports certificates and accounts from the local data store file.`,
}
