package certmanager

import (
	"crypto/tls"
	"fmt"
	"time"
)

type checkResults struct {
	err      error
	expiring bool
}

func checkHost(host string, port string) checkResults {
	result := checkResults{}

	if port == "" {
		port = "443"
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", host, port), nil)
	if err != nil {
		result.err = err
		return result
	}

	defer conn.Close()

	expiry := conn.ConnectionState().PeerCertificates[0].NotAfter
	fmt.Printf("Issuer: %s\nExpiry: %v\n", conn.ConnectionState().PeerCertificates[0].Issuer, expiry.Format(time.RFC850))

	// TODO: Check if cert is expiring soon.

	err = conn.VerifyHostname(host)
	if err != nil {
		result.err = err
		return result
	}


	return result
}
