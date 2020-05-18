package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
)

//
// DoPOP3 -
//
func DoPOP3(config *tls.Config, app string, server string, serverIP net.IP, port int) error {

	dialer := getDialer(defaultTCPTimeout)
	conn, err := dialer.Dial("tcp", addressString(serverIP, port))
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)
	scanner.Scan()
	line := scanner.Text()
	if scanner.Err() != nil {
		return fmt.Errorf("read error: %s", err.Error())
	}
	fmt.Printf("recv: %s\n", line)
	fmt.Printf("send: STLS\n")
	writer.WriteString("STLS\r\n")
	writer.Flush()
	scanner.Scan()
	line = scanner.Text()
	if scanner.Err() != nil {
		return fmt.Errorf("read error: %s", err.Error())
	}
	fmt.Printf("recv: %s\n", line)
	if !strings.HasPrefix(line, "+OK") {
		return fmt.Errorf("POP3 STARTTLS unavailable")
	}
	tlsconn := tls.Client(conn, config)
	err = tlsconn.Handshake()
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %s", err.Error())
	}
	printConnectionDetails(tlsconn.ConnectionState())
	tlsconn.Close()
	return err
}

//
// DoIMAP -
//
func DoIMAP(config *tls.Config, app string, server string, serverIP net.IP, port int) error {

	var gotSTARTTLS bool

	dialer := getDialer(defaultTCPTimeout)
	conn, err := dialer.Dial("tcp", addressString(serverIP, port))
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)
	scanner.Scan()
	line := scanner.Text()
	if scanner.Err() != nil {
		return fmt.Errorf("read error: %s", err.Error())
	}
	fmt.Printf("recv: %s\n", line)
	fmt.Printf("send: . CAPABILITY\n")
	writer.WriteString(". CAPABILITY\r\n")
	writer.Flush()
	for scanner.Scan() {
		line = scanner.Text()
		if scanner.Err() != nil {
			return fmt.Errorf("read error: %s", err.Error())
		}
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
	fmt.Printf("send: . STARTTLS\n")
	writer.WriteString(". STARTTLS\r\n")
	writer.Flush()
	scanner.Scan()
	line = scanner.Text()
	if scanner.Err() != nil {
		return fmt.Errorf("read error: %s", err.Error())
	}
	fmt.Printf("recv: %s\n", line)
	if !strings.HasPrefix(line, ". OK") {
		return fmt.Errorf("STARTTLS failed to negotiate")
	}
	tlsconn := tls.Client(conn, config)
	err = tlsconn.Handshake()
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %s", err.Error())
	}
	printConnectionDetails(tlsconn.ConnectionState())
	tlsconn.Close()
	return err
}

//
// parseSMTPline -
//
func parseSMTPline(line string) (int, string, error) {

	replycode, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, "", fmt.Errorf("invalid reply code: %s", line)
	}
	rest := line[4:]
	return replycode, rest, err
}

//
// DoSMTP -
//
func DoSMTP(config *tls.Config, app string, server string, serverIP net.IP, port int) error {

	var replycode int
	var rest string
	var gotSTARTTLS bool

	dialer := getDialer(defaultTCPTimeout)
	conn, err := dialer.Dial("tcp", addressString(serverIP, port))
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(conn)
	writer := bufio.NewWriter(conn)

	scanner.Scan()
	line := scanner.Text()
	if scanner.Err() != nil {
		return fmt.Errorf("read error: %s", err.Error())
	}
	fmt.Printf("recv: %s\n", line)
	replycode, _, err = parseSMTPline(line)
	if err != nil {
		return err
	}
	if replycode != 220 {
		return fmt.Errorf("invalid reply code in SMTP greeting")
	}

	fmt.Printf("send: EHLO localhost\n")
	writer.WriteString("EHLO localhost\r\n")
	writer.Flush()
	for scanner.Scan() {
		line = scanner.Text()
		if scanner.Err() != nil {
			return fmt.Errorf("read error: %s", err.Error())
		}
		fmt.Printf("recv: %s\n", line)
		replycode, rest, err = parseSMTPline(line)
		if err != nil {
			return err
		}
		if replycode != 250 {
			return fmt.Errorf("invalid reply code in EHLO response")
		}
		if strings.Contains(rest, "STARTTLS") {
			gotSTARTTLS = true
		}
		if line[3] != '-' {
			break
		}
	}
	if !gotSTARTTLS {
		return fmt.Errorf("SMTP STARTTLS support not detected")
	}

	fmt.Printf("send: STARTTLS\n")
	writer.WriteString("STARTTLS\r\n")
	writer.Flush()
	scanner.Scan()
	line = scanner.Text()
	if scanner.Err() != nil {
		return fmt.Errorf("read error: %s", err.Error())
	}
	fmt.Printf("recv: %s\n", line)
	replycode, _, err = parseSMTPline(line)
	if err != nil {
		return err
	}
	if replycode != 220 {
		return fmt.Errorf("invalid reply code in STARTTLS response")
	}
	tlsconn := tls.Client(conn, config)
	err = tlsconn.Handshake()
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %s", err.Error())
	}
	printConnectionDetails(tlsconn.ConnectionState())
	tlsconn.Close()
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
		_ = cs
		return fmt.Errorf("STARTLS not implemented for %s yet", app)

	default:
		_ = cs
		return fmt.Errorf("Unknown STARTTLS application: %s", app)
	}
}
