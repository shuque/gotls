package main

import (
	"net"
	"strconv"
	"strings"
	"time"
)

//
// AddressString - compose address string for net functions
//
func addressString(ipaddress net.IP, port int) string {

	addr := ipaddress.String()
	if strings.Index(addr, ":") == -1 {
		return addr + ":" + strconv.Itoa(port)
	}
	return "[" + addr + "]" + ":" + strconv.Itoa(port)
}

//
// getDialer -
//
func getDialer(timeout int) *net.Dialer {

	dialer := new(net.Dialer)
	dialer.Timeout = time.Second * time.Duration(timeout)
	return dialer
}

//
// getTCPconn() -
//
func getTCPconn(address net.IP, port int) (net.Conn, error) {

	dialer := getDialer(defaultTCPTimeout)
	conn, err := dialer.Dial("tcp", addressString(address, port))
	return conn, err
}
