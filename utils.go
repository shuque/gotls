package main

import (
	"net"
	"strconv"
	"strings"
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
