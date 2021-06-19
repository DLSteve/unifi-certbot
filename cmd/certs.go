package cmd

import (
	"errors"
	"fmt"
	"github.com/DLSteve/unifi-certbot/certs"
	"github.com/DLSteve/unifi-certbot/datastore"
	ucerrors "github.com/DLSteve/unifi-certbot/errors"
	"github.com/DLSteve/unifi-certbot/utilities"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"strings"
)

var ExportPath string

func init() {
	exportCmd.AddCommand(exportCertCmd)
	exportCertCmd.Flags().StringVarP(&ExportPath, "export-path", "p", "", "Export directory location")
}

var exportCertCmd = &cobra.Command{
	Use:   "cert [domain name]",
	Short: "Exports certificates",
	Long: `Exports certificates and private keys from the local data store file.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ds := datastore.GetBoltDataStore("")
		path := ExportPath
		if path == "" {
			curDir, err := os.Getwd()
			if err != nil {
				return err
			}
			path = curDir
		}

		exists, err := utilities.PathExists(path)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("provided path could not be found")
		}

		crt, err := ds.GetCerts(args[0])
		if err != nil {
			re, ok := err.(*ucerrors.DataStoreErr)
			if ok && re.NotFound {
				return fmt.Errorf("no certificates found for %s", args[0])
			} else {
				return err
			}
		}

		return writeCerts(args[0], path, crt)
	},
}

func writeCerts(domain string, path string, certs certs.LECerts) error {
	path = strings.TrimSuffix(path, "/")
	err := ioutil.WriteFile(fmt.Sprintf("%s/%s.crt", path, domain), []byte(certs.Certificate), 0640)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/%s.key", path, domain), []byte(certs.PrivateKey), 0640)
	if err != nil {
		return err
	}

	return nil
}
