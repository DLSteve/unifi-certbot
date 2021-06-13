package cmd

import (
	"github.com/DLSteve/unifi-certbot/certmanager"
	"github.com/DLSteve/unifi-certbot/datastore"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var email string
var host string
var sslPort string
var sshPort string
var sshUser string

func init() {
	viper.SetDefault("unifi.ssl-port", "443")
	viper.SetDefault("unifi.ssh-port", "22")
	viper.SetDefault("unifi.ssh-user", "root")
	rootCmd.AddCommand(updateCmd)
	updateCmd.PersistentFlags().StringVar(&email, "email", "EMAIL", "Email used for registering with Let's Encrypt")
	viper.BindPFlag("lets-encrypt.email", updateCmd.PersistentFlags().Lookup("email"))

	updateCmd.PersistentFlags().StringVar(&host, "host", "HOST", "Hostname/domain for the Unifi Dream Machine Pro")
	viper.BindPFlag("unifi.host", updateCmd.PersistentFlags().Lookup("host"))

	updateCmd.PersistentFlags().StringVar(&sslPort, "ssl-port", "SSL PORT", "Port used by the Unifi Dream Machine Pro for SSL")
	viper.BindPFlag("unifi.ssl-port", updateCmd.PersistentFlags().Lookup("ssl-port"))

	updateCmd.PersistentFlags().StringVar(&sshPort, "ssh-port", "SSL PORT", "Port used by the Unifi Dream Machine Pro for SSH")
	viper.BindPFlag("unifi.ssh-port", updateCmd.PersistentFlags().Lookup("ssh-port"))

	updateCmd.PersistentFlags().StringVar(&sshUser, "ssh-user", "SSL USER", "User used by the Unifi Dream Machine Pro for SSH")
	viper.BindPFlag("unifi.ssh-user", updateCmd.PersistentFlags().Lookup("ssh-user"))
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Checks the cert status and auto renews.",
	Long: `Checks the certificate status on the UDM Pro. If the certificate has expired or is invalid Unifi CertBot
will attempt to renew it.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ds := datastore.GetBoltDataStore("")
		cm := certmanager.CertManager{
			DS: ds,
		}
		err := cm.ValidateAndRenew(certmanager.CMOptions{
			Email:  viper.GetString("lets-encrypt.email"),
			Domain: viper.GetString("unifi.host"),
			SSLPort: viper.GetString("unifi.ssl-port"),
			SSHUser: viper.GetString("unifi.ssh-user"),
			SSHPassword: viper.GetString("unifi.ssh-password"),
			SSHPort: viper.GetString("unifi.ssh-port"),
		})
		if err != nil {
			return err
		}

		return nil
	},
}
