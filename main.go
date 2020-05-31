//
// gotls is a diagnostic tool that connects to a TLS server, performs DANE and
// PKIX authentication of the server of the server, and prints miscellaneous
// information about the certificates and DANE records.
//

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
var Version = "0.2.2"

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
// doTLSA obtains DANE TLSA records for the given hostname and port.
//
func doTLSA(resolver *dane.Resolver, hostname string, port int) *dane.TLSAinfo {

	tlsa, err := dane.GetTLSA(resolver, hostname, port)
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
// GetAddresses
//
func getAddresses(resolver *dane.Resolver, hostname string, secure bool) []net.IP {

	iplist, err := dane.GetAddresses(Options.resolver, hostname, secure)
	if err != nil {
		fmt.Printf("GetAddresses: %s\n", err)
		os.Exit(2)
	}
	if len(iplist) < 1 {
		fmt.Printf("No addresses found for %s.\n", hostname)
		os.Exit(2)
	}
	if debug {
		fmt.Printf("IP Addresses found:\n")
		for _, ip := range iplist {
			fmt.Printf("  %s\n", ip)
		}
	}
	return iplist
}

//
// getDaneConfig -
//
func getDaneConfig(hostname string, ip net.IP, port int) *dane.Config {

	var config *dane.Config

	config = dane.NewConfig(hostname, ip, port)
	config.NoVerify = Options.noverify
	config.DANE = Options.DANE
	config.PKIX = Options.PKIX
	config.DaneEEname = Options.DaneEEname
	config.SMTPAnyMode = Options.SMTPAnyMode
	if Options.appname != "" {
		config.SetAppName(Options.appname)
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

	if debug {
		fmt.Printf("Host: %s Port: %d\n", hostname, port)
		if Options.appname != "" {
			fmt.Printf("STARTTLS application: %s", Options.appname)
			if Options.sname != "" {
				fmt.Printf(", Service name: %s\n", Options.sname)
			} else {
				fmt.Println()
			}
		}
	}

	if Options.DANE {
		tlsa = doTLSA(Options.resolver, hostname, port)
	}
	needSecure = (tlsa != nil)
	iplist := getAddresses(Options.resolver, hostname, needSecure)

	countIP := len(iplist)
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

		if debug && !config.NoVerify && config.TLSA != nil {
			config.TLSA.Results()
		}

		if err != nil {
			fmt.Printf("Result: FAILED: %s\n", err.Error())
			continue
		}

		countSuccess++

		if debug {
			printConnectionDetails(conn, config)
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
