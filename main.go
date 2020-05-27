/*
 * gotls
 * Diagnostic tool that connects to a TLS server, performs DANE and PKIX
 * authentication of the server of the server, and prints miscellaneous
 * information about the certificates and DANE records.
 *
 */

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path"

	"github.com/shuque/dane"
)

// Version string
var Version = "0.2.0"

// Progname - Program name
var Progname string = path.Base(os.Args[0])

//
// finalResult -
//
func finalResult(ipcount, successcount int) {
	if Options.noverify {
		fmt.Printf("\n[4] Server authentication was not performed.\n")
		os.Exit(4)
	} else if successcount == ipcount {
		fmt.Printf("\n[0] Authentication succeeded for all (%d) peers.\n", ipcount)
		os.Exit(0)
	} else if successcount > 0 {
		fmt.Printf("\n[1] Authentication succeeded for some (%d of %d) peers.\n",
			successcount, ipcount)
		os.Exit(1)
	} else {
		fmt.Printf("\n[2] Authentication failed for all (%d) peers.\n", ipcount)
		os.Exit(2)
	}
}

//
// doTLSA -
//
func doTLSA(hostname string, port int) *dane.TLSAinfo {

	tlsa, err := dane.GetTLSA(Options.resolver, hostname, port)
	if err != nil {
		fmt.Printf("GetTLSA: %s\n", err.Error())
		os.Exit(2)
	}
	if tlsa == nil {
		fmt.Printf("No DANE TLSA records found.\n")
		if !Options.PKIX {
			os.Exit(2)
		}
	} else if debug {
		tlsa.Print()
	}

	return tlsa
}

//
// getDaneConfig -
//
func getDaneConfig(hostname string, ip net.IP, port int) *dane.Config {

	var server *dane.Server
	var config *dane.Config

	server = dane.NewServer(hostname, ip, port)
	config = dane.NewConfig()
	config.SetServer(server)
	config.NoVerify = Options.noverify
	config.DANE = Options.DANE
	config.PKIX = Options.PKIX
	config.DaneEEname = Options.DaneEEname
	config.SMTPAnyMode = Options.SMTPAnyMode
	if Options.starttls != "" {
		config.SetAppName(Options.starttls)
		config.SetServiceName(Options.sname)
	}

	return config
}

//
// main -
//
func main() {

	var err error
	var hostname string
	var port int
	var config *dane.Config
	var conn *tls.Conn
	var tlsa *dane.TLSAinfo
	var needSecure bool

	hostname, port = parseArgs(os.Args)

	if Options.DANE {
		tlsa = doTLSA(hostname, port)
	}

	needSecure = (tlsa != nil)
	iplist, err := dane.GetAddresses(Options.resolver, hostname, needSecure)
	if err != nil {
		fmt.Printf("GetAddresses: %s\n", err)
		os.Exit(2)
	}

	countIP := len(iplist)
	if countIP < 1 {
		fmt.Printf("No addresses found for %s.\n", hostname)
		os.Exit(2)
	}

	countSuccess := 0

	for _, ip := range iplist {

		fmt.Printf("\n## Checking %s %s port %d\n", hostname, ip, port)
		config = getDaneConfig(hostname, ip, port)
		config.SetTLSA(tlsa)

		if config.Appname == "" {
			conn, err = dane.DialTLS(config)
		} else {
			conn, err = dane.DialStartTLS(config)
		}

		if debug {
			if !config.NoVerify && config.TLSA != nil {
				config.TLSA.Results()
			}
		}

		if err != nil {
			fmt.Printf("Result: FAILED: %s\n", err.Error())
			continue
		}

		countSuccess++

		if debug {
			if config.Transcript != "" {
				fmt.Printf("## STARTTLS Transcript:\n%s", config.Transcript)
			}
			cs := conn.ConnectionState()
			fmt.Printf("## Peer Certificate Chain:\n")
			for i, cert := range cs.PeerCertificates {
				fmt.Printf("  %2d %v\n", i, cert.Subject)
				fmt.Printf("     %v\n", cert.Issuer)
			}
			if !config.NoVerify {
				printPKIXVerifiedChains(config.VerifiedChains)
			}
			printConnectionDetails(cs)
		}

		conn.Close()

		if config.Okdane {
			fmt.Printf("Result: DANE OK\n")
		} else if config.Okpkix {
			fmt.Printf("Result: PKIX OK\n")
		}
	}

	finalResult(countIP, countSuccess)
}
