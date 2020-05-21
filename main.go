/*
 * gotls
 * Diagnostic tool that connects to a TLS server, performs DANE and PKIX
 * authentication of the server of the server, and prints miscellaneous
 * information about the certificates and DANE records.
 *
 */

package main

import (
	"fmt"
	"os"
	"path"
	"time"
)

// Version string
var Version = "0.1.0"

// Progname - Program name
var Progname string = path.Base(os.Args[0])

// Defaults
var (
	defaultDNSTimeout   = 3
	defaultDNSRetries   = 3
	defaultTCPTimeout   = 4
	defaultResolverPort = 53
)

// Globals
var debug = false
var qopts = QueryOptions{adflag: true,
	rdflag:  true,
	payload: 1460,
	timeout: time.Second * time.Duration(defaultDNSTimeout),
	retries: defaultDNSRetries}
var tlsa *TLSAinfo

//
// main -
//
func main() {

	var err error
	var server string
	var port int

	server, port = parseArgs(os.Args)

	if Options.dane {
		tlsa, err = getTLSA(Options.resolver, Options.rport, server, port)
		if err != nil {
			fmt.Printf("%s. Use \"-m pkix\" for PKIX only.\n", err)
			fmt.Printf("\n[2] Authentication failed.\n")
			os.Exit(2)
		}
		if tlsa != nil {
			tlsa.Print()
		} else {
			if Options.pkix {
				fmt.Printf("No DANE TLSA records found. Falling back to PKIX-only.\n")
			} else {
				fmt.Printf("No DANE TLSA records found. Aborting.\n")
				fmt.Printf("\n[2] Authentication failed.\n")
				os.Exit(2)
			}
		}
	}

	ipList, err := getAddresses(Options.resolver, Options.rport, server)
	if err != nil {
		fmt.Printf("%s\n", err)
		os.Exit(2)
	}
	countIP := len(ipList)
	if countIP == 0 {
		fmt.Printf("No addresses found for %s.\n", server)
		os.Exit(2)
	}

	countSuccess := 0
	for _, ip := range ipList {
		fmt.Printf("\n## Checking %s %s port %d\n", server, ip, port)
		err = checkTLS(server, ip, port)
		if err != nil {
			fmt.Printf("%s\n", err.Error())
		} else {
			countSuccess++
		}
	}

	if Options.noverify {
		fmt.Printf("\n[4] Server authentication was not performed.\n")
		os.Exit(4)
	} else if countSuccess == countIP {
		fmt.Printf("\n[0] Authentication succeeded for all (%d) peers.\n", countIP)
		os.Exit(0)
	} else if countSuccess > 0 {
		fmt.Printf("\n[1] Authentication succeeded for some (%d of %d) peers.\n",
			countSuccess, countIP)
		os.Exit(1)
	} else {
		fmt.Printf("\n[2] Authentication failed for all (%d) peers.\n", countIP)
		os.Exit(2)
	}

}
