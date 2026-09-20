// SPDX-License-Identifier: Apache-2.0
package keyservice

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

func allowedPrefixes(address, configured string) ([]netip.Prefix, error) {
	if configured == "" {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("non-loopback service listener requires explicit allowed client CIDRs")
		}
		return []netip.Prefix{netip.PrefixFrom(ip, ip.BitLen())}, nil
	}
	var out []netip.Prefix
	for _, value := range strings.Split(configured, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid client CIDR")
		}
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("unrestricted client CIDR is not allowed")
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

type allowedListener struct {
	net.Listener
	prefixes []netip.Prefix
}

func (l *allowedListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(connection.RemoteAddr().String())
		if err == nil {
			ip, err := netip.ParseAddr(host)
			if err == nil {
				for _, prefix := range l.prefixes {
					if prefix.Contains(ip.Unmap()) {
						return connection, nil
					}
				}
			}
		}
		connection.Close()
	}
}
