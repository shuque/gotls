package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/shuque/dane"
)

// OptionsStruct - options
type OptionsStruct struct {
	TLSversion  string
	CAfile      string
	CAdata      []byte
	useV4       bool
	useV6       bool
	ipAddress   net.IP
	DANE        bool
	PKIX        bool
	SNI         string
	DaneEEname  bool
	noverify    bool
	SMTPAnyMode bool
	appname     string
	sname       string
	timeout     time.Duration
	resolver    *dane.Resolver
	rport       int
	printchain  bool
}

// Options -
var Options OptionsStruct

// Defaults
var (
	defaultDNSTimeout   = 3
	defaultDNSRetries   = 3
	defaultTCPTimeout   = 4
	defaultResolverPort = 53
)

// Globals
var debug = false

// parseArgs parses command line arguments.
func parseArgs(args []string) (hostname string, port int) {

	var err error
	var mode string

	help := flag.Bool("h", false, "Print this help string")
	flag.BoolVar(&debug, "d", false, "Debug mode")
	flag.StringVar(&Options.TLSversion, "version", "", "TLS version to use")
	flag.StringVar(&Options.CAfile, "cafile", "", "PKIX Root CA file in PEM format")
	flag.BoolVar(&Options.useV6, "6", false, "use IPv6 only")
	flag.BoolVar(&Options.useV4, "4", false, "use IPv4 only")
	flag.StringVar(&mode, "m", "", "Mode: dane or pkix")
	flag.StringVar(&Options.SNI, "sni", "", "SNI name to send and verify")
	flag.StringVar(&Options.appname, "s", "", "STARTTLS app (smtp,imap,pop3)")
	flag.StringVar(&Options.sname, "n", "", "Service name")
	tmpResolver := flag.String("r", "", "Resolver IP address")
	flag.IntVar(&Options.rport, "rp", defaultResolverPort, "Resolver port number")
	tmpTimeout := flag.Int("t", defaultDNSTimeout, "query timeout in seconds")
	flag.BoolVar(&Options.DaneEEname, "dane-ee-name", false, "DANE EE name")
	flag.BoolVar(&Options.SMTPAnyMode, "smtp-any-mode", false, "SMTP any mode")
	flag.BoolVar(&Options.noverify, "noverify", false, "noverify")
	flag.BoolVar(&Options.printchain, "printchain", false, "printchain")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
%s, version %s (built with go dane v%s)
Usage: %s [Options] <host> [<port>]

	If port is omitted, the default port 443 is used. If hostname is an
	IP address string, then a name must be specified via the SNI option.

	Options:
	-h               Print this help string
	-d               Debug mode - print additional info
	-m mode          Mode: "dane" or "pkix"
	-cafile FILE     PKIX Root CA file in PEM format
	-sni name        Specify SNI name to send and verify
	-s starttls      STARTTLS application (smtp, imap, pop3)
	-n name          Service name (if different from hostname)
	-version VER     TLS version to use (e.g. "1.3")
	-4               Use IPv4 transport only
	-6               Use IPv6 transport only
	-r ip            DNS Resolver IP address
	-rp port         DNS Resolver port (default %d)
	-t N             DNS query timeout value in seconds (default %d)
	-dane-ee-name    Do hostname check even for DANE-EE mode
	-smtp-any-mode   Allow STARTTLS SMTP for any DANE usage mode
	-noverify        Don't perform server certificate verification
	-printchain      Print details of full certificate chain
`, Progname, Version, dane.Version, Progname, defaultResolverPort, defaultDNSTimeout)
	}

	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(1)
	}

	if *tmpResolver != "" {
		resolverIP := net.ParseIP(*tmpResolver)
		if resolverIP == nil {
			fmt.Printf("Can't parse resolver IP address: %s\n", *tmpResolver)
			flag.Usage()
			os.Exit(3)
		}
		resolvers := []*dane.Server{dane.NewServer("", resolverIP, Options.rport)}
		Options.resolver = dane.NewResolver(resolvers)
	} else {
		Options.resolver, err = dane.GetResolver("")
		if err != nil {
			fmt.Printf("Error obtaining resolver address: %s", err.Error())
			os.Exit(3)
		}
	}

	Options.timeout = time.Second * time.Duration(*tmpTimeout)
	Options.resolver.Timeout = Options.timeout
	Options.resolver.Retries = defaultDNSRetries

	if Options.CAfile != "" {
		Options.CAdata, err = ioutil.ReadFile(Options.CAfile)
		if err != nil {
			fmt.Printf("Failed to read CA data: %s\n", err.Error())
			os.Exit(3)
		}
	}

	if Options.useV4 && Options.useV6 {
		fmt.Printf("Cannot specify both -4 and -6. Choose one.\n")
		flag.Usage()
		os.Exit(3)
	}

	if !(Options.useV4 || Options.useV6) {
		Options.useV4 = true
		Options.useV6 = true
	}
	Options.resolver.IPv6 = Options.useV6
	Options.resolver.IPv4 = Options.useV4

	switch mode {
	case "":
		Options.DANE = true
		Options.PKIX = true
	case "dane":
		Options.DANE = true
	case "pkix":
		Options.PKIX = true
	default:
		fmt.Printf("Invalid mode specified: %s\n", mode)
		flag.Usage()
		os.Exit(3)
	}

	if flag.NArg() == 1 {
		hostname = flag.Args()[0]
		port = 443
	} else if flag.NArg() == 2 {
		hostname = flag.Args()[0]
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

	Options.ipAddress = net.ParseIP(hostname)
	if Options.ipAddress != nil {
		if Options.SNI == "" {
			fmt.Printf("SNI must be specified with an IP address argument\n")
			os.Exit(2)
		}
	} else {
		if Options.SNI == "" {
			Options.SNI = hostname
		}
	}

	return hostname, port
}
