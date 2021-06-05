package cmd

import (
	"github.com/DLSteve/unifi-certbot/datastore"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
		_ = viper.GetString("dns-provider.cloud-flare.api-key")
		ds, err := datastore.GetBoltDataStore("")
		if err != nil {
			log.Fatal(err)
		}

		defer ds.Close()
	},
}
