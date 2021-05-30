package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(updateCmd)
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Checks the cert status and auto renews.",
	Long:  `Checks the certificate status on the UDM Pro. If the certificate has expired or is invalid Unifi CertBot
will attempt to renew it.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Some test output")
	},
}
