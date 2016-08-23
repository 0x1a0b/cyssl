package plugins

import (
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// ProtocolsDetector Detect supported protocols
type ProtocolsDetector struct {
}

// NewProtocolsDetector create a ProtocolsDetector
func NewProtocolsDetector() *ProtocolsDetector {
	return &ProtocolsDetector{}
}

// Name detector name
func (p ProtocolsDetector) Name() string {
	return "protocols"
}

// Detect the protocols, version & ciphersuites
func (p ProtocolsDetector) Detect(domain string, conn *tls.Conn) map[string]interface{} {
	vers := map[uint16]string{
		0x0300: "SSL 3.0",
		0x0301: "TLS 1.0",
		0x0302: "TLS 1.1",
		0x0303: "TLS 1.2",
	}
	ciphers := map[uint16]string{
		0x0005: "TLS_RSA_WITH_RC4_128_SHA",
		0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		0xc007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		0xc011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		0xc012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	}
	state := conn.ConnectionState()
	current := map[string]string{
		"version":     vers[state.Version],
		"cipherSuite": ciphers[state.CipherSuite],
	}

	wg := sync.WaitGroup{}

	dialer := &net.Dialer{Timeout: 30 * time.Second}

	check := func(ver uint16, verName string, done chan map[string]interface{}) {

		conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
			MaxVersion:         ver,
			InsecureSkipVerify: true,
		})

		defer wg.Done()

		if err != nil {
			done <- map[string]interface{}{
				verName: map[string]bool{"enabled": false},
			}
			return
		}
		defer conn.Close()

		done <- map[string]interface{}{
			verName: map[string]interface{}{
				"enabled":     true,
				"cipherSuite": ciphers[conn.ConnectionState().CipherSuite],
			},
		}
	}

	checkResult := make(chan map[string]interface{}, len(vers))
	for k, v := range vers {
		wg.Add(1)
		go check(k, v, checkResult)
	}
	wg.Wait()

	optional := make(map[string]interface{})
	for i := 0; i < len(vers); i++ {
		for k, v := range <-checkResult {
			optional[k] = v
		}
	}

	return map[string]interface{}{
		"default":  current,
		"optional": optional,
	}
}

var _ = PluginManager.Register(*NewProtocolsDetector())
