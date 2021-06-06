package user

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/go-acme/lego/v4/registration"
)

type LEUser struct {
	Email        string
	NewUser      bool
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *LEUser) GetEmail() string {
	return u.Email
}
func (u LEUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *LEUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func (u *LEUser) IsNew() bool {
	return u.NewUser
}

func (u *LEUser) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Email      string `json:"email"`
		PrivateKey string `json:"private_key"`
	}{
		Email:      u.Email,
		PrivateKey: encode(u.Key.(*ecdsa.PrivateKey)),
	})
}

func (u *LEUser) UnmarshalJSON(data []byte) error {
	aux := &struct {
		Email      string `json:"email"`
		PrivateKey string `json:"private_key"`
	}{}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	u.Email = aux.Email
	u.Key = decode(aux.PrivateKey)
	return nil
}

func encode(privateKey *ecdsa.PrivateKey) string {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	return string(pemEncoded)
}

func decode(pemEncoded string) crypto.PrivateKey {
	block, _ := pem.Decode([]byte(pemEncoded))
	x509Encoded := block.Bytes
	privateKey, _ := x509.ParseECPrivateKey(x509Encoded)
	return privateKey
}
