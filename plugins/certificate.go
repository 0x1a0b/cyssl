package plugins

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"reflect"
	"time"
)

// CertDetector Detect and get certificate info for given domain
type CertDetector struct {
	rootCerts map[string]*x509.Certificate
}

// NewCertDetector create CertDetector
func NewCertDetector() *CertDetector {
	var certFiles = []string{
		"/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu/Gentoo etc.
		"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora/RHEL
		"/etc/ssl/ca-bundle.pem",             // OpenSUSE
		"/etc/pki/tls/cacert.pem",            // OpenELEC

		"certs/aosp.pem",
		"certs/apple.pem",
		"certs/java.pem",
		"certs/microsoft.pem",
		"certs/mozilla.pem",
	}

	hasRootCerts := false
	certDetector := &CertDetector{map[string]*x509.Certificate{}}

	for _, file := range certFiles {
		pemCerts, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}
		hasRootCerts = true
		// log.Printf("Load certs in %s", file)
		// code from AppendCertsFromPEM
		for len(pemCerts) > 0 {
			var block *pem.Block
			block, pemCerts = pem.Decode(pemCerts)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			certDetector.rootCerts[hex.EncodeToString(cert.SubjectKeyId)] = cert
		}
	}

	if !hasRootCerts {
		log.Fatal("Fail to init root certs: can't find root certs")
	}

	return certDetector
}

// Whether cert match hostname
func (d CertDetector) verifyHostname(cert *x509.Certificate, domain string) string {
	if cert.VerifyHostname(domain) == nil {
		return "matched"
	}
	return "mismatched"
}

// Whether sign algorithm is secure, MD2WithRSA & MD5WithRSA &SHA1WithRSA is not secure
func (d CertDetector) verifySignAlgorithm(cert *x509.Certificate) string {
	weakAlgorithms := map[x509.SignatureAlgorithm]bool{
		x509.MD2WithRSA:  true,
		x509.MD5WithRSA:  true,
		x509.SHA1WithRSA: true,
	}
	if ok := weakAlgorithms[cert.SignatureAlgorithm]; ok {
		return "weak"
	}
	return "ok"
}

// Cert valid days, negative says expired
func (d CertDetector) getValidDays(cert *x509.Certificate) string {
	delta := cert.NotAfter.Sub(time.Now())
	valid := int(delta.Hours()) / 24
	if valid > 0 {
		return fmt.Sprintf("%d days", valid)
	}
	return "expired"
}

// gen subject's map data
func (d CertDetector) genSubject(cert *x509.Certificate) map[string]interface{} {
	subject := map[string]interface{}{
		"commonName":       cert.Subject.CommonName,
		"organization":     cert.Subject.Organization,
		"organizationUnit": cert.Subject.OrganizationalUnit,
		"country":          cert.Subject.Country,
		"province":         cert.Subject.Province,
		"locality":         cert.Subject.Locality,
		"streetAddress":    cert.Subject.StreetAddress,
	}
	//flatten slice that with only one element
	for k, v := range subject {
		s := reflect.ValueOf(v)
		if s.Type().Kind() == reflect.Slice {
			if s.Len() == 1 {
				subject[k] = s.Index(0).String()
			}
		}
	}
	return subject
}

// gen issuer's map data
func (d CertDetector) genIssuer(cert *x509.Certificate) map[string]interface{} {
	issuer := map[string]interface{}{
		"commonName":       cert.Issuer.CommonName,
		"organization":     cert.Issuer.Organization,
		"organizationUnit": cert.Issuer.OrganizationalUnit,
		"country":          cert.Issuer.Country,
		"province":         cert.Issuer.Province,
		"locality":         cert.Issuer.Locality,
		"streetAddress":    cert.Issuer.StreetAddress,
	}
	//flatten slice that with only one element
	for k, v := range issuer {
		i := reflect.ValueOf(v)
		if i.Type().Kind() == reflect.Slice {
			if i.Len() == 1 {
				issuer[k] = i.Index(0).String()
			}
		}
	}
	return issuer
}

// gen public key's map with name/bits length/exponents/status
func (d CertDetector) genPublicKey(cert *x509.Certificate) map[string]interface{} {
	result := map[string]interface{}{}
	if key, ok := reflect.ValueOf(cert.PublicKey).Elem().FieldByName("N").Interface().(*big.Int); ok {
		// convert public algorithm to string
		publicAlgos := [...]string{
			x509.UnknownPublicKeyAlgorithm: "UnknownPublicKeyAlgorithm",
			x509.RSA:                       "RSA",
			x509.DSA:                       "DSA",
			x509.ECDSA:                     "ECDSA",
		}

		result["algorithm"] = publicAlgos[cert.PublicKeyAlgorithm]
		result["bits"] = key.BitLen()
		result["exponents"] = reflect.ValueOf(cert.PublicKey).Elem().FieldByName("E").Int()

		// whether public key is weak
		if cert.PublicKeyAlgorithm == x509.RSA && key.BitLen() < 2048 {
			result["status"] = "weak"
		} else {
			result["status"] = "ok"
		}
	}
	return result
}

// gen signatureAlgorith map with name/status
func (d CertDetector) genSignAlgo(cert *x509.Certificate) map[string]interface{} {
	weakAlgorithms := map[x509.SignatureAlgorithm]bool{
		x509.MD2WithRSA:  true,
		x509.MD5WithRSA:  true,
		x509.SHA1WithRSA: true,
	}

	result := map[string]interface{}{
		"algorithm": cert.SignatureAlgorithm.String(),
		"status":    "ok",
	}

	if ok := weakAlgorithms[cert.SignatureAlgorithm]; ok {
		result["status"] = "weak"
	}
	return result
}

// GetServerCert extract certificate detail data, and get what we focus on
//
// There are many reasons why a certificate may not be trusted. The exact
// problem is indicated on the report card in bright red. The problems fall
// into three categories:
//
//     1. Invalid certificate
//     2. Invalid configuration
//     3. Unknown Certificate Authority
//
// 1. Invalid certificate
//
// A certificate is invalid if:
//
//     * It is used before its activation date
//     * It is used after its expiry date
//     * Certificate hostnames don't match the site hostname
//     * It has been revoked TODO
//
// 2. Invalid configuration
//
// In some cases, the certificate chain does not contain all the necessary
// certificates to connect the web server certificate to one of the root
// certificates in our trust store. Less commonly, one of the certificates
// in the chain (other than the web server certificate) will have expired,
// and that invalidates the entire chain.
//
// 3. Unknown Certificate Authority
//
// In order for trust to be established, we must have the root certificate
// of the signing Certificate Authority in our trust store. SSL Labs does not
// maintain its own trust store; instead we use the store maintained by Mozilla.
//
// If we mark a web site as not trusted, that means that the average web user's
// browser will not trust it either. For certain special groups of users, such
// web sites can still be secure. For example, if you can securely verify that
// a self-signed web site is operated by a person you trust, then you can trust
// that self-signed web site too. Or, if you work for an organisation that  manages
// its own trust, and you have their own root certificate already embedded in
// your browser. Such special cases do not work for the general public, however,
// and this is what we indicate on our report card.
func (d CertDetector) GetServerCert(certs []*x509.Certificate, domain string) map[string]interface{} {
	r := make(map[string]interface{})
	if len(certs) > 1 {
		c := certs[0]
		r["trusted"] = true
		if time.Now().After(c.NotAfter) || time.Now().Before(c.NotBefore) {
			r["trusted"] = false
		}
		hostnameMatched := d.verifyHostname(c, domain)
		// see rules description in comment above
		if hostnameMatched != "matched" {
			r["trusted"] = false
		}

		r["hostname"] = hostnameMatched
		r["issuer"] = d.genIssuer(c)
		r["subject"] = d.genSubject(c)
		r["SANs"] = c.DNSNames
		r["validFrom"] = c.NotBefore.Format("2006-01-02 15:04:05")
		r["validUntil"] = c.NotAfter.Format("2006-01-02 15:04:05")
		r["validDays"] = d.getValidDays(c)
		r["key"] = d.genPublicKey(c)
		r["signatureAlgorithm"] = d.genSignAlgo(c)
	}

	return r
}

// GetAdditionalCerts extract additional certificate detail data, and get what we focus on
func (d CertDetector) GetAdditionalCerts(certs []*x509.Certificate) map[string]interface{} {
	list := []map[string]interface{}{}
	if len(certs) >= 2 {
		for _, c := range certs[1:] {
			list = append(list, map[string]interface{}{
				"issuer":        c.Issuer.CommonName,
				"commonName":    c.Subject.CommonName,
				"signAlgorithm": d.genSignAlgo(c),
				"validFrom":     c.NotBefore.Format("2006-01-02 15:04:05"),
				"validUntil":    c.NotAfter.Format("2006-01-02 15:04:05"),
				"key":           d.genPublicKey(c),
			})
		}
	}

	paths := map[string]interface{}{"list": list, "chainIssue": nil}
	issues := []string{}
	// only contains server cert, missing chains
	if len(certs) < 2 {
		paths["chainIssue"] = append(issues, "too short")
	} else if len(certs) > 10 {
		paths["chainIssue"] = append(issues, "too many")
	} else {
		aKey := certs[0].AuthorityKeyId
		for _, c := range certs[1:] {
			// simply check
			if bytes.Compare(aKey, c.SubjectKeyId) != 0 {
				paths["chainIssue"] = append(issues, "incorrect order")
				break
			}
			aKey = c.AuthorityKeyId
		}

		for _, c := range certs[1:] {
			if bytes.Compare(c.SubjectKeyId, c.AuthorityKeyId) == 0 {
				paths["chainIssue"] = append(issues, "contains anchor")
				break
			}
		}
	}
	return paths
}

// GetCertChains extract cert chains detail data, and get what we focus on
func (d CertDetector) GetCertChains(certs []*x509.Certificate) map[string]interface{} {
	// extract what we want, called with every cert in path
	extract := func(c *x509.Certificate, source string) map[string]interface{} {
		r := make(map[string]interface{})
		r["commonName"] = c.Subject.CommonName
		r["signatureAlgorithm"] = d.genSignAlgo(c)
		r["key"] = d.genPublicKey(c)
		r["source"] = source
		r["expired"] = time.Now().After(c.NotAfter) || time.Now().Before(c.NotBefore)
		if bytes.Compare(c.SubjectKeyId, c.AuthorityKeyId) == 0 {
			r["selfSigned"] = true
		} else {
			r["selfSigned"] = false
		}
		return r
	}

	// put certs in a map with cert's subjectKey as mapKey
	certsMap := map[string]*x509.Certificate{}
	for _, c := range certs[1:] {
		certsMap[hex.EncodeToString(c.SubjectKeyId)] = c
	}

	// first is server cert
	serverCert := certs[0]
	aKey := hex.EncodeToString(serverCert.AuthorityKeyId)

	result := map[string]interface{}{"trusted": true}
	pathList := []interface{}{extract(serverCert, "Sent by server")}

	// find authority one by one in certsMap or trust store
	for {
		if c, ok := d.rootCerts[aKey]; ok {
			pathList = append(pathList, extract(c, "In trust store"))
			break
		} else if c, ok := certsMap[aKey]; ok {
			pathList = append(pathList, extract(c, "Sent by server"))
			if bytes.Compare(c.SubjectKeyId, c.AuthorityKeyId) == 0 || // self-signed
				time.Now().After(c.NotAfter) || time.Now().Before(c.NotBefore) { // whether expired
				result["trusted"] = false
			}
			delete(certsMap, aKey)
			aKey = hex.EncodeToString(c.AuthorityKeyId)
		} else {
			// Invalid config or Unknown CA
			result["trusted"] = false
			break
		}
	}
	result["list"] = pathList

	return result
}

// Name detector's name
func (d CertDetector) Name() string {
	return "certificate"
}

// Detect do scan and return result
func (d CertDetector) Detect(domain string, conn *tls.Conn) map[string]interface{} {
	result := make(map[string]interface{})

	if conn != nil {
		certs := conn.ConnectionState().PeerCertificates

		result["server"] = d.GetServerCert(certs, domain)
		result["addtional"] = d.GetAdditionalCerts(certs)

		paths := d.GetCertChains(certs)
		result["path"] = paths

		// if path is untrusted, so is server cert
		if t, _ := paths["trusted"].(bool); !t {
			r, _ := result["server"].(map[string]interface{})
			r["trusted"] = false
		}
	}

	return result
}

var _ = PluginManager.Register(*NewCertDetector())
