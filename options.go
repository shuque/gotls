package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/miekg/dns"
)

//
// OptionsStruct - options
//
type OptionsStruct struct {
	verbose  bool
	useV4    bool
	useV6    bool
	dane     bool
	pkix     bool
	timeout  time.Duration
	retries  int
	resolver net.IP
}

// Options -
var Options OptionsStruct

//
// parseArgs() - parse command line arguments.
//
func parseArgs(args []string) (server string, port int) {

	var err error
	var mode string

	help := flag.Bool("h", false, "Print this help string")
	flag.BoolVar(&Options.useV6, "6", false, "use IPv6 only")
	flag.BoolVar(&Options.useV4, "4", false, "use IPv4 only")
	flag.StringVar(&mode, "m", "", "Mode: dane or pkix")
	tmpString := flag.String("r", "", "Resolver IP address")
	tmpInt := flag.Int("t", defaultDNSTimeout, "query timeout in seconds")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
%s, version %s
Usage: %s [Options] <host> [<port>]

	If unspecified, the default port 443 is used.

	Options:
	-h          Print this help string
	-m mode     Mode: "dane" or "pkix"
	-r ip       DNS Resolver IP address
	-4          Use IPv4 transport only
	-6          Use IPv6 transport only
	-t N        Query timeout value in seconds (default %d)
`, Progname, Version, Progname, defaultDNSTimeout)
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(1)
	}

	if *tmpString != "" {
		Options.resolver = net.ParseIP(*tmpString)
		if Options.resolver == nil {
			fmt.Printf("Can't parse resolver IP address: %s\n", *tmpString)
			flag.Usage()
			os.Exit(3)
		}
	} else {
		Options.resolver, err = getResolver()
		if err != nil {
			fmt.Printf("Error obtaining resolver address: %s", err.Error())
			os.Exit(3)
		}
	}

	Options.timeout = time.Second * time.Duration(*tmpInt)

	if Options.useV4 && Options.useV6 {
		fmt.Printf("Cannot specify both -4 and -6. Choose one.\n")
		flag.Usage()
		os.Exit(3)
	}

	if !(Options.useV4 || Options.useV6) {
		Options.useV4 = true
		Options.useV6 = true
	}

	switch mode {
	case "":
		Options.dane = true
		Options.pkix = true
	case "dane":
		Options.dane = true
	case "pkix":
		Options.pkix = true
	default:
		fmt.Printf("Invalid mode specified: %s\n", mode)
		flag.Usage()
		os.Exit(3)
	}

	if flag.NArg() == 1 {
		server = flag.Args()[0]
		port = 443
	} else if flag.NArg() == 2 {
		server = flag.Args()[0]
		port, err = strconv.Atoi(flag.Args()[1])
		if err != nil {
			fmt.Printf("Invalid port: %s\n", flag.Args()[1])
			flag.Usage()
			os.Exit(3)
		}
	} else {
		flag.Usage()
		os.Exit(3)
	}

	return dns.Fqdn(server), port
}
