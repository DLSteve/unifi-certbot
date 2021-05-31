package cmd

import (
	"github.com/DLSteve/unifi-certbot/dnsprovider"
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
		apiKey := viper.GetString("dns-provider.cloud-flare.api-key")

		dns := dnsprovider.NewCloudFlareProvider(apiKey)

		if err := dns.CreateDnsTextEntry("bandsaw.io", "unifi.core.bandsaw.io", "some text here2"); err != nil {
			log.Fatal(err)
		}
	},
}
