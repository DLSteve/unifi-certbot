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

	currentTime := time.Now()
	if IsExpiring(conn.ConnectionState().PeerCertificates[0], currentTime) {
		result.expiring = true
		return result
	}

	err = conn.VerifyHostname(host)
	if err != nil {
		result.err = err
		return result
	}


	return result
}
