package datastore

import "github.com/DLSteve/unifi-certbot/user"

type DataStore interface {
	SaveUser(user *user.LEUser) error
	GetUser(email string) (*user.LEUser, error)
}

