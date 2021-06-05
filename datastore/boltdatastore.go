package datastore

import (
	bolt "go.etcd.io/bbolt"
	"time"
)

func GetBoltDataStore(path string) (DataStore, error) {
	if path == "" {
		path = "./unifi-certbot.db"
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	return &boltDataStore{
		db: db,
	}, nil
}

type boltDataStore struct {
	db *bolt.DB
}

func (b *boltDataStore) Close() error {
	return b.db.Close()
}
