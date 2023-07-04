package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/shuque/dane"
)

// TLSversion2string - map TLS verson number to string
var TLSversion2string = map[uint16]string{
	tls.VersionTLS10: "1.0",
	tls.VersionTLS11: "1.1",
	tls.VersionTLS12: "1.2",
	tls.VersionTLS13: "1.3",
}

// TLSstring2version - map TLS version string to number
var TLSstring2version = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

// KeyUsage value to string
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

// ExtendedKeyUsage value to string
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

// KU2Strings -
func KU2Strings(ku x509.KeyUsage) string {

	var result []string
	for k, v := range KeyUsage {
		if ku&k == k {
			result = append(result, v)
		}
	}
	return strings.Join(result, " ")
}

// EKU2Strings -
func EKU2Strings(ekulist []x509.ExtKeyUsage) string {

	var result []string
	for _, eku := range ekulist {
		result = append(result, ExtendedKeyUsage[eku])
	}
	return strings.Join(result, " ")
}

// KeySizeInBits -
func KeySizeInBits(publickey interface{}) int {

	switch v := publickey.(type) {
	case *rsa.PublicKey:
		return v.Size() * 8
	case *ecdsa.PublicKey:
		return v.X.BitLen() + v.Y.BitLen()
	case *ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// printCertDetails --
// Print some details of the certificate.
func printCertDetails(cert *x509.Certificate) {

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
	fmt.Printf("   PublicKey Algorithm: %v %d-Bits\n",
		cert.PublicKeyAlgorithm, KeySizeInBits(cert.PublicKey))
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
}

// printCertChainDetails -
func printCertChainDetails(chain []*x509.Certificate) {

	fmt.Printf("## -------------- FULL Certificate Chain ----------------\n")
	for i, cert := range chain {
		fmt.Printf("## Certificate at Depth: %d\n", i)
		printCertDetails(cert)
	}
}

// printCertChains -
func printCertChains(chains [][]*x509.Certificate, name string) {

	for i, row := range chains {
		fmt.Printf("## %s Certificate Chain %d:\n", name, i)
		for j, cert := range row {
			fmt.Printf("  %2d %v\n", j, cert.Subject)
			fmt.Printf("     %v\n", cert.Issuer)
		}
	}
}

// printConnectionDetails -
func printConnectionDetails(conn *tls.Conn, config *dane.Config) {

	var peerCerts []*x509.Certificate
	cs := conn.ConnectionState()

	if config.Transcript != "" {
		fmt.Printf("## STARTTLS Transcript:\n%s", config.Transcript)
	}

	fmt.Printf("## Peer Certificate Chain:\n")
	for i, cert := range cs.PeerCertificates {
		fmt.Printf("  %2d %v\n", i, cert.Subject)
		fmt.Printf("     %v\n", cert.Issuer)
	}
	if !config.NoVerify {
		printCertChains(config.PKIXChains, "PKIX")
	}
	if config.DANE {
		printCertChains(config.DANEChains, "DANE")
	}
	fmt.Printf("## TLS Connection Info:\n")
	fmt.Printf("   TLS version: %s\n", TLSversion2string[cs.Version])
	fmt.Printf("   CipherSuite: %s\n", tls.CipherSuiteName(cs.CipherSuite))
	if cs.NegotiatedProtocol != "" {
		fmt.Printf("NegotiatedProtocol: %s\n", cs.NegotiatedProtocol)
	}

	peerCerts = cs.PeerCertificates
	if Options.printchain {
		printCertChainDetails(peerCerts)
	} else if debug {
		fmt.Printf("## End-Entity Certificate Info:\n")
		printCertDetails(peerCerts[0])
	}
}
