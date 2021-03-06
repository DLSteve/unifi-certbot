package datastore

import (
	"encoding/json"
	"errors"
	"github.com/DLSteve/unifi-certbot/certs"
	ucberrors "github.com/DLSteve/unifi-certbot/errors"
	"github.com/DLSteve/unifi-certbot/user"
	bolt "go.etcd.io/bbolt"
	"time"
)

func GetBoltDataStore(path string) DataStore {
	if path == "" {
		path = "./unifi-certbot.db"
	}

	return &boltDataStore{
		path: path,
	}
}

type boltDataStore struct {
	path string
}

func (b *boltDataStore) SaveUser(user *user.LEUser) error {
	email := user.GetEmail()
	var jsonData []byte
	jsonData, err := json.Marshal(user)
	if err != nil {
		return &ucberrors.DataStoreErr{
			Err: err,
		}
	}

	db, err := b.open()
	if err != nil {
		return &ucberrors.DataStoreErr{
			Err: err,
		}
	}
	defer db.Close()

	return db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("users"))
		if err != nil {
			return &ucberrors.DataStoreErr{
				Err: err,
			}
		}

		return bucket.Put([]byte(email), jsonData)
	})
}

func (b *boltDataStore) GetUser(email string) (*user.LEUser, error) {
	db, err := b.open()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	var usr user.LEUser
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("users"))
		if bucket == nil {
			return &ucberrors.DataStoreErr{
				NotFound: true,
				Err: errors.New("unable to find user bucket"),
			}
		}
		usrJson := bucket.Get([]byte(email))
		if usrJson == nil {
			return &ucberrors.DataStoreErr{
				NotFound: true,
				Err: errors.New("unable to find user for given email"),
			}
		}

		err = json.Unmarshal(usrJson, &usr)
		if err != nil {
			return &ucberrors.DataStoreErr{
				Err: err,
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &usr, nil
}

func (b *boltDataStore) SaveCerts(domain string, certs certs.LECerts) error {
	var jsonData []byte
	jsonData, err := json.Marshal(certs)
	if err != nil {
		return &ucberrors.DataStoreErr{
			Err: err,
		}
	}

	db, err := b.open()
	if err != nil {
		return &ucberrors.DataStoreErr{
			Err: err,
		}
	}
	defer db.Close()

	return db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("certs"))
		if err != nil {
			return &ucberrors.DataStoreErr{
				Err: err,
			}
		}

		return bucket.Put([]byte(domain), jsonData)
	})
}

func (b *boltDataStore) GetCerts(domain string) (certs.LECerts, error) {
	db, err := b.open()
	if err != nil {
		return certs.LECerts{}, err
	}
	defer db.Close()

	var crt certs.LECerts
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("certs"))
		if bucket == nil {
			return &ucberrors.DataStoreErr{
				NotFound: true,
				Err: errors.New("unable to find certs bucket"),
			}
		}
		certJson := bucket.Get([]byte(domain))
		if certJson == nil {
			return &ucberrors.DataStoreErr{
				NotFound: true,
				Err: errors.New("unable to find cert for given domain"),
			}
		}

		err = json.Unmarshal(certJson, &crt)
		if err != nil {
			return &ucberrors.DataStoreErr{
				Err: err,
			}
		}

		return nil
	})
	if err != nil {
		return certs.LECerts{}, err
	}

	return crt, nil
}

func (b *boltDataStore) open() (*bolt.DB, error) {
	db, err := bolt.Open(b.path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, &ucberrors.DataStoreErr{
			Err: err,
		}
	}

	return db, nil
}
