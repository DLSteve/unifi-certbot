package certmanager

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/DLSteve/unifi-certbot/certs"
	"github.com/DLSteve/unifi-certbot/datastore"
	"github.com/DLSteve/unifi-certbot/errors"
	"github.com/DLSteve/unifi-certbot/user"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
)

type CMOptions struct {
	Email       string
	Domain      string
	SSLPort     string
	SSHUser     string
	SSHPort     string
	SSHPassword string
}

type CertManager struct {
	DS datastore.DataStore
}

func (c *CertManager) GetUser(email string) (*user.LEUser, error) {
	usr, err := c.DS.GetUser(email)
	if err != nil {
		re, ok := err.(*errors.DataStoreErr)
		if ok && re.NotFound {
			log.Println("user not found, creating new private key")
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, err
			}
			usr = &user.LEUser{
				Email:   email,
				NewUser: true,
				Key:     privateKey,
			}
			err = c.DS.SaveUser(usr)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return usr, nil
}

func (c *CertManager) RenewCertificate(domain string, email string) (certs.LECerts, error) {
	usr, err := c.GetUser(email)
	if err != nil {
		return certs.LECerts{}, err
	}

	config := lego.NewConfig(usr)
	// STAGE API - For testing only
	// config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return certs.LECerts{}, err
	}

	cfConf := cloudflare.NewDefaultConfig()
	cfConf.AuthToken = viper.GetString("unifi.dns-provider.api-key")

	cfProvider, err := cloudflare.NewDNSProviderConfig(cfConf)
	if err != nil {
		return certs.LECerts{}, err
	}
	err = client.Challenge.SetDNS01Provider(cfProvider)
	if err != nil {
		return certs.LECerts{}, err
	}

	if usr.IsNew() {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return certs.LECerts{}, err
		}
		usr.Registration = reg
	} else {
		reg, err := client.Registration.ResolveAccountByKey()
		if err != nil {
			return certs.LECerts{}, err
		}
		usr.Registration = reg
	}

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return certs.LECerts{}, err
	}

	return certs.LECerts{
		PrivateKey:        string(certificates.PrivateKey),
		Certificate:       string(certificates.Certificate),
		IssuerCertificate: string(certificates.IssuerCertificate),
	}, nil
}

func (c *CertManager) HostCertIsValid(domain string, port string) bool {
	results := checkHost(domain, port)
	if results.err != nil {
		log.Println(results.err)
		return false
	}

	return true
}

func (c *CertManager) ValidateAndRenew(options CMOptions) error {
	ok := c.HostCertIsValid(options.Domain, options.SSLPort)
	if !ok {
		var notFound bool
		crt, err := c.DS.GetCerts(options.Domain)
		if err != nil {
			re, ok := err.(*errors.DataStoreErr)
			if ok {
				notFound = re.NotFound
			} else {
				return err
			}
		}

		if notFound {
			crt, err = c.RenewCertificate(options.Domain, options.Email)
			if err != nil {
				return err
			}

			err = c.DS.SaveCerts(options.Domain, crt)
			if err != nil {
				return err
			}
		}

		return DeployCerts(options, crt)
	}
	return nil
}

func DeployCerts(options CMOptions, crt certs.LECerts) error {
	configRoot := "/mnt/data/unifi-os/unifi-core/config"
	client, err := GetSSHClient(options)
	if err != nil {
		return err
	}

	defer client.Close()

	// Backup old certs
	log.Println("Backing up cert file")
	err = RunSSHCommand(client, fmt.Sprintf("mv %s/unifi-core.crt %s/unifi-core.crt.backup", configRoot, configRoot))
	if err != nil {
		log.Println("Error backing up cert file")
	}

	log.Println("Backing up key file")
	err = RunSSHCommand(client, fmt.Sprintf("mv %s/unifi-core.key %s/unifi-core.key.backup", configRoot, configRoot))
	if err != nil {
		log.Println("Error backing up key file")
	}

	log.Println("Writing cert file")
	err = RunSSHCommand(client, fmt.Sprintf("echo \"%s\" > %s/unifi-core.crt", crt.Certificate, configRoot))
	if err != nil {
		log.Println("Error writing cert file")
	}

	log.Println("Writing key file")
	err = RunSSHCommand(client, fmt.Sprintf("echo \"%s\" > %s/unifi-core.key", crt.PrivateKey, configRoot))
	if err != nil {
		log.Println("Error writing key file")
	}

	log.Println("Updating permissions")
	err = RunSSHCommand(client, fmt.Sprintf("chmod 644 -R %s", configRoot))
	if err != nil {
		log.Println("Error updating permissions")
	}

	log.Println("Restarting UnifiOS")
	err = RunSSHCommand(client, "unifi-os restart")
	if err != nil {
		return err
	}

	return nil
}

func GetSSHClient(options CMOptions) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: options.SSHUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(options.SSHPassword),
		},
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(options.Domain, options.SSHPort), config)
	if err != nil {
		return nil, err
	}

	return client, err
}

func RunSSHCommand(client *ssh.Client, cmd string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	var b bytes.Buffer
	session.Stdout = &b
	session.Stderr = &b
	err = session.Run(cmd)
	if err != nil {
		return err
	}
	if b.String() != "" {
		log.Println(b.String())
	}
	return nil
}
