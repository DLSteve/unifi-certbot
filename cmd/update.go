package cmd

import (
	"fmt"
	"github.com/DLSteve/unifi-certbot/certmanager"
	"github.com/DLSteve/unifi-certbot/datastore"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
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
		ds := datastore.GetBoltDataStore("")
		cm := certmanager.CertManager{
			DS: ds,
		}

		usr, err := cm.GetUser("")
		if err != nil {
			log.Fatal(err)
		}

		config := lego.NewConfig(usr)
		config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
		config.Certificate.KeyType = certcrypto.RSA2048

		client, err := lego.NewClient(config)
		if err != nil {
			log.Fatal(err)
		}

		cfConf := cloudflare.NewDefaultConfig()
		cfConf.AuthToken = viper.GetString("dns-provider.cloud-flare.api-key")

		cfProvider, err := cloudflare.NewDNSProviderConfig(cfConf)
		if err != nil {
			log.Fatal(err)
		}
		err = client.Challenge.SetDNS01Provider(cfProvider)
		if err != nil {
			log.Fatal(err)
		}

		if usr.IsNew() {
			reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
			if err != nil {
				log.Fatal(err)
			}
			usr.Registration = reg
		} else {
			reg, err := client.Registration.ResolveAccountByKey()
			if err != nil {
				log.Fatal(err)
			}
			usr.Registration = reg
		}

		request := certificate.ObtainRequest{
			Domains: []string{"unifi.core.bandsaw.io"},
			Bundle:  true,
		}
		certificates, err := client.Certificate.Obtain(request)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%#v\n", certificates)
	},
}
