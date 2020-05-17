package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

//
// Globals
//
var okpkix bool
var okdane bool

//
// TLSversion - map TLS verson number to string
//
var TLSversion = map[uint16]string{
	0x0300: "SSL3.0",
	0x0301: "TLS1.0",
	0x0302: "TLS1.1",
	0x0303: "TLS1.2",
	0x0304: "TLS1.3",
}

//
// KeyUsage value to string
//
var KeyUsage = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "DigitalSignature",
	x509.KeyUsageContentCommitment: "ContentCommitment",
	x509.KeyUsageKeyEncipherment:   "KeyEncipherment",
	x509.KeyUsageDataEncipherment:  "DataEncipherment",
	x509.KeyUsageKeyAgreement:      "KeyAgreement",
	x509.KeyUsageCertSign:          "CertSign",
	x509.KeyUsageCRLSign:           "CRLSign",
	x509.KeyUsageEncipherOnly:      "EncipherOnly",
	x509.KeyUsageDecipherOnly:      "DecipherOnly",
}

//
// ExtendedKeyUsage value to string
//
var ExtendedKeyUsage = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "ServerAuth",
	x509.ExtKeyUsageClientAuth:                     "ClientAuth",
	x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
	x509.ExtKeyUsageEmailProtection:                "EmailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
	x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
}

//
// KU2Strings -
//
func KU2Strings(ku x509.KeyUsage) string {

	var result []string
	for k, v := range KeyUsage {
		if ku&k == k {
			result = append(result, v)
		}
	}
	return strings.Join(result, " ")
}

//
// EKU2Strings -
//
func EKU2Strings(ekulist []x509.ExtKeyUsage) string {

	var result []string
	for _, eku := range ekulist {
		result = append(result, ExtendedKeyUsage[eku])
	}
	return strings.Join(result, " ")
}

//
// printCertDetails --
// Print some details of the certificate.
//
func printCertDetails(cert *x509.Certificate) {

	fmt.Printf("## Certificate Info:\n")
	fmt.Printf("   X509 version: %d\n", cert.Version)
	fmt.Printf("   Serial#: %x\n", cert.SerialNumber)
	fmt.Printf("   Subject: %v\n", cert.Subject)
	fmt.Printf("   Issuer:  %v\n", cert.Issuer)
	for _, dnsName := range cert.DNSNames {
		fmt.Printf("   SAN dNSName: %s\n", dnsName)
	}
	for _, ipAddress := range cert.IPAddresses {
		fmt.Printf("   SAN IPaddress: %s\n", ipAddress)
	}
	for _, emailAddress := range cert.EmailAddresses {
		fmt.Printf("   SAN emailAddress: %s\n", emailAddress)
	}
	for _, uri := range cert.URIs {
		fmt.Printf("   SAN URI: %v\n", uri)
	}
	fmt.Printf("   Signature Algorithm: %v\n", cert.SignatureAlgorithm)
	fmt.Printf("   PublicKey Algorithm: %v\n", cert.PublicKeyAlgorithm)
	fmt.Printf("   Inception:  %v\n", cert.NotBefore)
	fmt.Printf("   Expiration: %v\n", cert.NotAfter)
	fmt.Printf("   KU: %v\n", KU2Strings(cert.KeyUsage))
	fmt.Printf("   EKU: %v\n", EKU2Strings(cert.ExtKeyUsage))
	if cert.BasicConstraintsValid {
		fmt.Printf("   Is CA?: %v\n", cert.IsCA)
	}
	fmt.Printf("   SKI: %x\n", cert.SubjectKeyId)
	fmt.Printf("   AKI: %x\n", cert.AuthorityKeyId)
	fmt.Printf("   OSCP Servers: %v\n", cert.OCSPServer)
	fmt.Printf("   CA Issuer URL: %v\n", cert.IssuingCertificateURL)
	fmt.Printf("   CRL Distribution: %v\n", cert.CRLDistributionPoints)
	fmt.Printf("   Policy OIDs: %v\n", cert.PolicyIdentifiers)
	return
}

//
// computeTLSA --
//
func computeTLSA(tlsaRdata *TLSArdata, cert *x509.Certificate) (string, error) {

	var preimage asn1.RawContent
	var output []byte
	var tmp256 [32]byte
	var tmp512 [64]byte

	switch tlsaRdata.selector {
	case 0:
		preimage = cert.Raw
	case 1:
		preimage = cert.RawSubjectPublicKeyInfo
	default:
		return "", fmt.Errorf("Unknown TLSA selector: %d", tlsaRdata.selector)
	}

	switch tlsaRdata.mtype {
	case 0:
		output = preimage
	case 1:
		tmp256 = sha256.Sum256(preimage)
		output = tmp256[:]
	case 2:
		tmp512 = sha512.Sum512(preimage)
		output = tmp512[:]
	default:
		return "", fmt.Errorf("Unknown TLSA matching type: %d", tlsaRdata.mtype)
	}
	return hex.EncodeToString(output), nil
}

//
// chainMatchesTLSA -
// Check that TLSA record data has a corresponding match in the certificate chain.
//
func chainMatchesTLSA(chain []*x509.Certificate, tlsaRdata *TLSArdata) bool {

	var Authenticated = false
	var hash string
	var err error

	switch tlsaRdata.usage {
	case 1, 3:
		hash, err = computeTLSA(tlsaRdata, chain[0])
		if err != nil {
			fmt.Printf(err.Error())
			break
		}
		if hash == tlsaRdata.data {
			fmt.Printf("   OK:   %s matched EE certificate.\n", tlsaRdata)
			if tlsaRdata.usage == 1 && okpkix {
				Authenticated = true
			} else if tlsaRdata.usage == 3 {
				Authenticated = true
			}
		}
	case 0, 2:
		for i, cert := range chain[1:] {
			hash, err = computeTLSA(tlsaRdata, cert)
			if err != nil {
				fmt.Printf(err.Error())
				break
			}
			if hash == tlsaRdata.data {
				fmt.Printf("   OK:   %s matched certificate at depth %d.\n", tlsaRdata, i+1)
				if tlsaRdata.usage == 0 && okpkix {
					Authenticated = true
				} else if tlsaRdata.usage == 2 {
					Authenticated = true
				}
			}
		}
	default:
		fmt.Printf("Unknown TLSA usage mode: %d\n", tlsaRdata.usage)
	}

	if !Authenticated {
		fmt.Printf("   WARN: %s did not match certificate.\n", tlsaRdata)
	}
	return Authenticated
}

//
// daneAuthenticationSingleChain -
// Perform DANE authentication of a single certificate chain. TLSA rdata is
// obtained from the global "tlsa" struct.
//
func daneAuthenticationSingleChain(chain []*x509.Certificate) bool {

	var Authenticated, ok bool

	for _, tlsaRdata := range tlsa.rdata {
		ok = chainMatchesTLSA(chain, tlsaRdata)
		if ok {
			Authenticated = true
		}
	}

	return Authenticated
}

//
// daneAuthenticationAllChains -
// Perform DANE authentication of a set of certificate chains. If there are
// multiple chains, usually one is a superset of another. So we just return
// true, once a single chain authenticates. And return false if no chain
// authenticates.
//
func daneAuthenticationAllChains(chains [][]*x509.Certificate) bool {

	var ok bool

	for _, chain := range chains {
		ok = daneAuthenticationSingleChain(chain)
		if ok {
			return true
		}
	}
	return false
}

//
// printPKIXVerifiedChains -
//
func printPKIXVerifiedChains(chains [][]*x509.Certificate) {

	for i, row := range chains {
		fmt.Printf("## PKIX Verified Chain %d:\n", i)
		for j, cert := range row {
			fmt.Printf("  %2d %v\n", j, cert.Subject)
			fmt.Printf("     %v\n", cert.Issuer)
		}
	}
	return
}

//
// verifyPKIX -
// Perform PKIX certificate chain validation of the given chain (certs)
// If "root" is true, then use the systems root certificate store. Otherwise,
// set the tail certificate of the chain as the root (self signed mode)
//
func verifyPKIX(certs []*x509.Certificate, config *tls.Config,
	root bool) ([][]*x509.Certificate, error) {

	var verifiedChains [][]*x509.Certificate
	var err error

	if root {
		opts := x509.VerifyOptions{
			Roots:         config.RootCAs,
			DNSName:       config.ServerName,
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		verifiedChains, err = certs[0].Verify(opts)
	} else {
		opts := x509.VerifyOptions{
			Roots:   x509.NewCertPool(),
			DNSName: config.ServerName,
		}
		chainlength := len(certs)
		last := certs[chainlength-1]
		opts.Roots.AddCert(last)
		if chainlength >= 3 {
			opts.Intermediates = x509.NewCertPool()
			for _, cert := range certs[1:] {
				opts.Intermediates.AddCert(cert)
			}
		}
		verifiedChains, err = certs[0].Verify(opts)
	}
	return verifiedChains, err
}

//
// verifyServer -
//
func verifyServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate,
	config *tls.Config) error {

	var err error
	certs := make([]*x509.Certificate, len(rawCerts))

	fmt.Printf("## Peer Certificate Chain:\n")
	for i, asn1Data := range rawCerts {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			return errors.New("failed to parse server certificate: " + err.Error())
		}
		certs[i] = cert
		fmt.Printf("  %2d %v\n", i, cert.Subject)
		fmt.Printf("     %v\n", cert.Issuer)
	}

	verifiedChains, err = verifyPKIX(certs, config, true)
	if err == nil {
		okpkix = true
		printPKIXVerifiedChains(verifiedChains)
	}

	if !(Options.dane && tlsa != nil) {
		return err
	}

	fmt.Printf("## DANE TLS authentication result:\n")
	if !okpkix && len(certs) > 1 {
		verifiedChains, err = verifyPKIX(certs, config, false)
		if err != nil {
			return fmt.Errorf("DANE TLS error: cert chain: %s", err.Error())
		}
	}

	if verifiedChains != nil {
		okdane = daneAuthenticationAllChains(verifiedChains)
	} else {
		okdane = daneAuthenticationSingleChain(certs)
	}
	if !okdane {
		return fmt.Errorf("DANE TLS authentication failed")
	}

	return nil
}

//
// printConnectionDetails -
//
func printConnectionDetails(cs tls.ConnectionState) {

	var peerCerts []*x509.Certificate

	fmt.Printf("## TLS Connection Info:\n")
	fmt.Printf("   TLS version: %s\n", TLSversion[cs.Version])
	fmt.Printf("   CipherSuite: %s\n", tls.CipherSuiteName(cs.CipherSuite))
	if cs.NegotiatedProtocol != "" {
		fmt.Printf("NegotiatedProtocol: %s\n", cs.NegotiatedProtocol)
	}
	peerCerts = cs.PeerCertificates
	printCertDetails(peerCerts[0])
	return
}

//
// getTLSconfig -
//
func getTLSconfig(server string) *tls.Config {

	config := new(tls.Config)
	config.ServerName = server
	if Options.dane {
		config.InsecureSkipVerify = true
	} else {
		config.InsecureSkipVerify = false
	}
	config.VerifyPeerCertificate = func(rawCerts [][]byte,
		verifiedChains [][]*x509.Certificate) error {
		return verifyServer(rawCerts, verifiedChains, config)
	}
	return config
}

//
// checkTLS - check server TLS and certificate config
//
func checkTLS(server string, serverIP net.IP, port int) error {

	var err error
	config := getTLSconfig(server)

	if Options.starttls != "" {
		err = startTLS(config, Options.starttls, server, serverIP, port)
		if err != nil {
			return fmt.Errorf("starttls error: %s", err.Error())
		}
	} else {
		dialer := new(net.Dialer)
		dialer.Timeout = time.Second * time.Duration(defaultTCPTimeout)
		conn, err := tls.DialWithDialer(dialer, "tcp", addressString(serverIP, port), config)
		if err != nil {
			return fmt.Errorf("failed to connect to %s, %s: %s",
				server, serverIP, err.Error())
		}
		cs := conn.ConnectionState()
		printConnectionDetails(cs)
		conn.Close()
	}

	return err
}
