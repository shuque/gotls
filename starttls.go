package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
)

//
// startTLS -
//
func startTLS(tlsconfig *tls.Config, app string, server string, serverIP net.IP, port int) error {

	var cs tls.ConnectionState

	fmt.Printf("## STARTTLS application: %s\n", app)

	switch app {

	case "smtp":
		c, err := smtp.Dial(addressString(serverIP, port))
		if err != nil {
			return err
		}
		err = c.StartTLS(tlsconfig)
		if err != nil {
			return err
		}
		cs, ok := c.TLSConnectionState()
		if !ok {
			return fmt.Errorf("TLS conn state unavailable")
		}
		printConnectionDetails(cs)
		c.Quit()
		return err

	case "imap", "pop", "xmpp-client", "xmpp-server":
		_ = cs
		return fmt.Errorf("STARTLS not implemented for %s yet", app)

	default:
		_ = cs
		return fmt.Errorf("Unknown STARTTLS application: %s", app)
	}
}
