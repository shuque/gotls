package main

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

//
// Default parameters
//
var (
	TimeoutInitial time.Duration = time.Second * 2
	TimeoutTCP     time.Duration = time.Second * 5
	Retries                      = 3
	BufsizeDefault uint16        = 1460
)

// EdnsoptStruct - Generic EDNS option
type EdnsoptStruct struct {
	code uint16
	data string // hex-encoded data string
}

//
// ResponseInfo - Response Information structure
//
type ResponseInfo struct {
	qname     string
	qtype     string
	qclass    string
	truncated bool
	retried   bool
	timeout   bool
	response  *dns.Msg
	rtt       time.Duration
	err       error
}

//
// Query - DNS query structure
//
type Query struct {
	qname  string
	qtype  uint16
	qclass uint16
}

//
// Set query components
//
func (q *Query) Set(qname string, qtype uint16, qclass uint16) {
	q.qname = qname
	q.qtype = qtype
	q.qclass = qclass
}

//
// getQuery - get populated Query struct
//
func getQuery(qname string, qtype uint16, qclass uint16) Query {
	var query Query
	query.Set(qname, qtype, qclass)
	return query
}

//
// QueryOptions - query options
//
type QueryOptions struct {
	rdflag  bool
	adflag  bool
	cdflag  bool
	timeout time.Duration
	retries int
	payload uint16
}

//
// TLSArdata - TLSA rdata structure
//
type TLSArdata struct {
	usage    uint8
	selector uint8
	mtype    uint8
	data     string
}

//
// TLSA rdata string function
//
func (tr *TLSArdata) String() string {
	return fmt.Sprintf("DANE TLSA %d %d %d [%s..]",
		tr.usage, tr.selector, tr.mtype, tr.data[0:8])
}

//
// TLSAinfo - TLSA info structure
//
type TLSAinfo struct {
	qname string
	alias []string
	rdata []*TLSArdata
}

//
// Print TLSAinfo
//
func (t *TLSAinfo) Print() {
	fmt.Printf("DNS TLSA RRset:\n  qname: %s\n", t.qname)
	if t.alias != nil {
		fmt.Printf("  alias: %s\n", t.alias)
	}
	for _, trdata := range t.rdata {
		fmt.Printf("  %d %d %d %s\n", trdata.usage, trdata.selector,
			trdata.mtype, trdata.data)
	}
}

//
// GetResolver - obtain (1st) system default resolver address
//
func getResolver() (resolver net.IP, err error) {

	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil {
		resolver = net.ParseIP(config.Servers[0])
	}
	return resolver, err
}

//
// MakeQuery - construct a DNS query MakeMessage
//
func makeQuery(query Query, qopts QueryOptions) *dns.Msg {

	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = qopts.rdflag
	m.AuthenticatedData = qopts.adflag
	m.CheckingDisabled = qopts.cdflag
	m.SetEdns0(qopts.payload, true)
	m.Question = make([]dns.Question, 1)
	m.Question[0] = dns.Question{Name: query.qname, Qtype: query.qtype,
		Qclass: query.qclass}
	return m
}

//
// SendQueryUDP - send DNS query via UDP
//
func sendQueryUDP(query Query, resolver net.IP, qopts QueryOptions) (*dns.Msg, error) {

	var response *dns.Msg
	var err error

	destination := addressString(resolver, 53)

	m := makeQuery(query, qopts)

	c := new(dns.Client)
	c.Net = "udp"
	c.Timeout = qopts.timeout

	retries := qopts.retries
	for retries > 0 {
		response, _, err = c.Exchange(m, destination)
		if err == nil {
			break
		}
		if nerr, ok := err.(net.Error); ok && !nerr.Timeout() {
			break
		}
		retries--
	}

	return response, err
}

//
// SendQueryTCP - send DNS query via TCP
//
func sendQueryTCP(query Query, resolver net.IP, qopts QueryOptions) (*dns.Msg, error) {

	var response *dns.Msg
	var err error

	destination := addressString(resolver, 53)
	m := makeQuery(query, qopts)

	c := new(dns.Client)
	c.Net = "tcp"
	c.Timeout = qopts.timeout

	response, _, err = c.Exchange(m, destination)
	return response, err

}

//
// SendQuery - send DNS query via UDP with fallback to TCP upon truncation
//
func sendQuery(query Query, resolver net.IP, qopts QueryOptions) (*dns.Msg, error) {

	var response *dns.Msg
	var err error

	response, err = sendQueryUDP(query, resolver, qopts)

	if err == nil && response.MsgHdr.Truncated {
		response, err = sendQueryTCP(query, resolver, qopts)
	}

	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("Error: null DNS response to query")
	}
	return response, err
}

//
// responseOK --
//
func responseOK(response *dns.Msg) bool {

	switch response.MsgHdr.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return true
	default:
		return false
	}
}

//
// getAddresses -
// Obtain list of IPv4 and IPv6 addresses for given hostname
//
func getAddresses(resolver net.IP, hostname string) ([]net.IP, error) {

	var ipList []net.IP
	var q Query
	var rrTypes []uint16

	if Options.useV6 {
		rrTypes = append(rrTypes, dns.TypeAAAA)
	}
	if Options.useV4 {
		rrTypes = append(rrTypes, dns.TypeA)
	}

	for _, rrtype := range rrTypes {
		q = getQuery(hostname, rrtype, dns.ClassINET)
		response, err := sendQuery(q, resolver, qopts)
		if err != nil {
			break
		}
		if !responseOK(response) {
			return nil, fmt.Errorf("Address lookup response rcode: %d", response.MsgHdr.Rcode)
		}
		if response.MsgHdr.Rcode == dns.RcodeNameError {
			return nil, fmt.Errorf("%s: Non-existent domain name", hostname)
		}
		if Options.dane && tlsa != nil && !response.MsgHdr.AuthenticatedData {
			return nil, fmt.Errorf("Address response was not authenticated")
		}

		for _, rr := range response.Answer {
			if rr.Header().Rrtype == rrtype {
				if rrtype == dns.TypeAAAA {
					ipList = append(ipList, rr.(*dns.AAAA).AAAA)
				} else if rrtype == dns.TypeA {
					ipList = append(ipList, rr.(*dns.A).A)
				}
			}
		}
	}

	return ipList, nil
}

//
// getTLSA()
//
func getTLSA(resolver net.IP, hostname string, port int) (*TLSAinfo, error) {

	var q Query
	var tr *TLSArdata

	qname := fmt.Sprintf("_%d._tcp.%s", port, hostname)

	q = getQuery(qname, dns.TypeTLSA, dns.ClassINET)
	response, err := sendQuery(q, resolver, qopts)

	if err != nil {
		return nil, err
	}

	if !responseOK(response) {
		return nil, fmt.Errorf("TLSA response rcode: %s",
			dns.RcodeToString[response.MsgHdr.Rcode])
	}

	if !response.MsgHdr.AuthenticatedData {
		if Options.pkix {
			fmt.Printf("WARNING: Unauthenticated TLSA response.\n")
			return nil, nil
		}
		return nil, fmt.Errorf("ERROR: TLSA response was unauthenticated")
	}

	if len(response.Answer) == 0 {
		return nil, err
	}

	t := new(TLSAinfo)
	t.qname = dns.Fqdn(qname)

	for _, rr := range response.Answer {
		if tlsa, ok := rr.(*dns.TLSA); ok {
			if tlsa.Hdr.Name != t.qname {
				t.alias = append(t.alias, tlsa.Hdr.Name)
			}
			tr = new(TLSArdata)
			tr.usage = tlsa.Usage
			tr.selector = tlsa.Selector
			tr.mtype = tlsa.MatchingType
			tr.data = tlsa.Certificate
			t.rdata = append(t.rdata, tr)
		}
	}

	return t, err
}
