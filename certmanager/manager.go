package certmanager

import (
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
	"log"
)

type CMOptions struct {
	Email  string
	Domain string
	Port   string
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
	config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		return certs.LECerts{}, err
	}

	cfConf := cloudflare.NewDefaultConfig()
	cfConf.AuthToken = viper.GetString("dns-provider.cloud-flare.api-key")

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

func (c *CertManager) CertIsValid(domain string, port string) bool {
	results := checkHost(domain, port)
	if results.err != nil {
		log.Println(results.err)
		return false
	}

	return true
}

func (c *CertManager) ValidateAndRenew(options CMOptions) error {
	ok := c.CertIsValid(options.Domain, options.Port)
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
		}

		fmt.Println(crt.Certificate)
	}
	return nil
}
