package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const bufsize = 2048

//
// getTCPconn() -
//
func getTCPconn(address net.IP, port int) (net.Conn, error) {

	dialer := getDialer(defaultTCPTimeout)
	conn, err := dialer.Dial("tcp", addressString(address, port))
	return conn, err
}

//
// TLShandshake -
//
func TLShandshake(conn net.Conn, config *tls.Config) error {

	tlsconn := tls.Client(conn, config)
	err := tlsconn.Handshake()
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %s", err.Error())
	}
	printConnectionDetails(tlsconn.ConnectionState())
	tlsconn.Close()
	return err
}

//
// DoXMPP -
// See RFC 6120, Section 5.4.2 for details
//
func DoXMPP(config *tls.Config, app string, server string, serverIP net.IP, port int) error {

	var servicename, rolename, line string
	buf := make([]byte, bufsize)

	conn, err := getTCPconn(serverIP, port)
	if err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	if Options.sname != "" {
		servicename = Options.sname
	} else {
		servicename = server
	}

	switch app {
	case "xmpp-client":
		rolename = "client"
	case "xmpp-server":
		rolename = "server"
	}

	outstring := fmt.Sprintf(
		"<?xml version='1.0'?><stream:stream to='%s' "+
			"version='1.0' xml:lang='en' xmlns='jabber:%s' "+
			"xmlns:stream='http://etherx.jabber.org/streams'>",
		servicename, rolename)
	fmt.Printf("send: %s\n", outstring)
	writer.WriteString(outstring)
	writer.Flush()

	_, err = reader.Read(buf)
	if err != nil {
		return err
	}
	line = string(buf)
	fmt.Printf("recv: %s\n", line)

	gotSTARTTLS := false
	if strings.Contains(line, "<starttls") && strings.Contains(line,
		"urn:ietf:params:xml:ns:xmpp-tls") {
		gotSTARTTLS = true
	}
	if !gotSTARTTLS {
		return fmt.Errorf("XMPP STARTTLS unavailable")
	}

	outstring = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
	fmt.Printf("send: %s\n", outstring)
	writer.WriteString(outstring + "\r\n")
	writer.Flush()

	_, err = reader.Read(buf)
	if err != nil {
		return err
	}
	line = string(buf)
	fmt.Printf("recv: %s\n", line)
	if !strings.Contains(line, "<proceed") {
		return fmt.Errorf("XMPP STARTTLS command failed")
	}

	err = TLShandshake(conn, config)
	return err
}

//
// DoPOP3 -
//
func DoPOP3(config *tls.Config, app string, server string, serverIP net.IP, port int) error {

	var line string

	conn, err := getTCPconn(serverIP, port)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read POP3 greeting
	line, err = reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")
	fmt.Printf("recv: %s\n", line)

	// Send STLS command
	fmt.Printf("send: STLS\n")
	writer.WriteString("STLS\r\n")
	writer.Flush()

	// Read STLS response, look for +OK
	// Read POP3 greeting
	line, err = reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")
	fmt.Printf("recv: %s\n", line)
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("POP3 STARTTLS unavailable")
	}

	err = TLShandshake(conn, config)
	return err
}

//
// DoIMAP -
//
func DoIMAP(config *tls.Config, app string, server string, serverIP net.IP, port int) error {

	var gotSTARTTLS bool
	var line string

	conn, err := getTCPconn(serverIP, port)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read IMAP greeting
	line, err = reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")
	fmt.Printf("recv: %s\n", line)

	// Send Capability command, read response, looking for STARTTLS
	fmt.Printf("send: . CAPABILITY\n")
	writer.WriteString(". CAPABILITY\r\n")
	writer.Flush()

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		fmt.Printf("recv: %s\n", line)
		if strings.HasPrefix(line, "* CAPABILITY") && strings.Contains(line, "STARTTLS") {
			gotSTARTTLS = true
		}
		if strings.HasPrefix(line, ". OK") {
			break
		}
	}

	if !gotSTARTTLS {
		return fmt.Errorf("IMAP STARTTLS capability unavailable")
	}

	// Send STARTTLS
	fmt.Printf("send: . STARTTLS\n")
	writer.WriteString(". STARTTLS\r\n")
	writer.Flush()

	// Look for OK response
	line, err = reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")
	fmt.Printf("recv: %s\n", line)
	if !strings.HasPrefix(line, ". OK") {
		return fmt.Errorf("STARTTLS failed to negotiate")
	}

	err = TLShandshake(conn, config)
	return err
}

//
// parseSMTPline -
//
func parseSMTPline(line string) (int, string, bool, error) {

	var responseDone = false

	replycode, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, "", responseDone, fmt.Errorf("invalid reply code: %s", line)
	}
	if line[3] != '-' {
		responseDone = true
	}
	rest := line[4:]
	return replycode, rest, responseDone, err
}

//
// DoSMTP -
//
func DoSMTP(config *tls.Config, app string, server string, serverIP net.IP, port int) error {

	var replycode int
	var line, rest string
	var responseDone, gotSTARTTLS bool

	conn, err := getTCPconn(serverIP, port)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Read possibly multi-line SMTP greeting
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		fmt.Printf("recv: %s\n", line)
		replycode, _, responseDone, err = parseSMTPline(line)
		if err != nil {
			return err
		}
		if responseDone {
			break
		}
	}
	if replycode != 220 {
		return fmt.Errorf("invalid reply code in SMTP greeting")
	}

	// Send EHLO, read possibly multi-line response, look for STARTTLS
	fmt.Printf("send: EHLO localhost\n")
	writer.WriteString("EHLO localhost\r\n")
	writer.Flush()

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		fmt.Printf("recv: %s\n", line)
		replycode, rest, responseDone, err = parseSMTPline(line)
		if err != nil {
			return err
		}
		if replycode != 250 {
			return fmt.Errorf("invalid reply code in EHLO response")
		}
		if strings.Contains(rest, "STARTTLS") {
			gotSTARTTLS = true
		}
		if responseDone {
			break
		}
	}

	if !gotSTARTTLS {
		return fmt.Errorf("SMTP STARTTLS support not detected")
	}

	// Send STARTTLS command and read success reply code
	fmt.Printf("send: STARTTLS\n")
	writer.WriteString("STARTTLS\r\n")
	writer.Flush()

	line, err = reader.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimRight(line, "\r\n")
	fmt.Printf("recv: %s\n", line)
	replycode, _, _, err = parseSMTPline(line)
	if err != nil {
		return err
	}
	if replycode != 220 {
		return fmt.Errorf("invalid reply code to STARTTLS command")
	}

	// Execute TLS handshake
	err = TLShandshake(conn, config)
	return err
}

//
// startTLS -
//
func startTLS(config *tls.Config, app string, server string, serverIP net.IP, port int) error {

	var cs tls.ConnectionState

	fmt.Printf("## STARTTLS application: %s\n", app)

	switch app {

	case "smtp":
		err := DoSMTP(config, app, server, serverIP, port)
		return err

	case "imap":
		err := DoIMAP(config, app, server, serverIP, port)
		return err

	case "pop3":
		err := DoPOP3(config, app, server, serverIP, port)
		return err

	case "xmpp-client", "xmpp-server":
		err := DoXMPP(config, app, server, serverIP, port)
		return err

	default:
		_ = cs
		return fmt.Errorf("Unknown STARTTLS application: %s", app)
	}
}
