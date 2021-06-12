package cmd

import (
	"github.com/DLSteve/unifi-certbot/certmanager"
	"github.com/DLSteve/unifi-certbot/datastore"
	"github.com/spf13/cobra"
	"log"
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
		ds := datastore.GetBoltDataStore("")
		cm := certmanager.CertManager{
			DS: ds,
		}
		err := cm.ValidateAndRenew(certmanager.CMOptions{
			Email: "",
			Domain: "",
		})
		if err != nil {
			log.Fatal(err)
		}
	},
}
