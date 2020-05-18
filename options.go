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
	verbose     bool
	useV4       bool
	useV6       bool
	sname       string
	dane        bool
	pkix        bool
	daneEEname  bool
	noverify    bool
	smtpAnyMode bool
	starttls    string
	timeout     time.Duration
	retries     int
	resolver    net.IP
	printchain  bool
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
	flag.StringVar(&Options.starttls, "s", "", "STARTTLS app (smtp,imap,pop3)")
	flag.StringVar(&Options.sname, "n", "", "Service name")
	tmpString := flag.String("r", "", "Resolver IP address")
	tmpInt := flag.Int("t", defaultDNSTimeout, "query timeout in seconds")
	flag.BoolVar(&Options.daneEEname, "dane-ee-name", false, "DANE EE name")
	flag.BoolVar(&Options.smtpAnyMode, "smtp-any-mode", false, "SMTP any mode")
	flag.BoolVar(&Options.noverify, "noverify", false, "noverify")
	flag.BoolVar(&Options.printchain, "printchain", false, "printchain")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
%s, version %s
Usage: %s [Options] <host> [<port>]

	If unspecified, the default port 443 is used.

	Options:
	-h               Print this help string
	-m mode          Mode: "dane" or "pkix"
	-s starttls      STARTTLS application (smtp, imap, pop3)
	-n name          Service name (if different from hostname)
	-4               Use IPv4 transport only
	-6               Use IPv6 transport only
	-r ip            DNS Resolver IP address
	-t N             Query timeout value in seconds (default %d)
	-dane-ee-name    Do hostname check even for DANE-EE mode
	-smtp-any-mode   Allow STARTTLS SMTP for any DANE usage mode
	-noverify        Don't perform server certificate verification
	-printchain      Print details of full certificate chain
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
		fmt.Printf("Invalid arguments\n")
		flag.Usage()
		os.Exit(3)
	}

	return dns.Fqdn(server), port
}
