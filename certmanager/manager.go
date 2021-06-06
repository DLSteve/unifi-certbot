package certmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/DLSteve/unifi-certbot/datastore"
	"github.com/DLSteve/unifi-certbot/errors"
	"github.com/DLSteve/unifi-certbot/user"
	"log"
)

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
				Email: email,
				NewUser: true,
				Key: privateKey,
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
