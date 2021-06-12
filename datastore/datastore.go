package datastore

import (
	"github.com/DLSteve/unifi-certbot/certs"
	"github.com/DLSteve/unifi-certbot/user"
)

type DataStore interface {
	SaveUser(user *user.LEUser) error
	GetUser(email string) (*user.LEUser, error)
	SaveCerts(domain string, certs certs.LECerts) error
	GetCerts(domain string) (certs.LECerts, error)
}

