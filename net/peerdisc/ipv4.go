package peerdisc

// Ported from monad-peer-discovery/src/ipv4_validation.rs.
// Rejects unspecified/special IPs outright; private/loopback/link-local
// peer addresses are allowed only if self is in the same class.

import (
	"errors"
	"net/netip"
)

var (
	ErrUnspecifiedIP = errors.New("peerdisc: unspecified ip")
	ErrSpecialIP     = errors.New("peerdisc: special-use ip")
	ErrPrivateIP     = errors.New("peerdisc: private ip")
	ErrLoopbackIP    = errors.New("peerdisc: loopback ip")
	ErrLinkLocalIP   = errors.New("peerdisc: link-local ip")
)

var documentationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
}

func isDocumentation(ip netip.Addr) bool {
	for _, p := range documentationPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func isBroadcast(ip netip.Addr) bool {
	return ip.Is4() && ip.As4() == [4]byte{255, 255, 255, 255}
}

// validateSocketIPv4Address — Rust validate_socket_ipv4_address.
func validateSocketIPv4Address(peer, self netip.AddrPort) error {
	peerIP, selfIP := peer.Addr(), self.Addr()

	if peerIP.IsUnspecified() {
		return ErrUnspecifiedIP
	}
	// special use: multicast (224/4), broadcast (255.255.255.255), docs
	if peerIP.IsMulticast() || isBroadcast(peerIP) || isDocumentation(peerIP) {
		return ErrSpecialIP
	}
	if peerIP.IsLoopback() && !selfIP.IsLoopback() {
		return ErrLoopbackIP
	}
	if peerIP.IsPrivate() && !selfIP.IsPrivate() {
		return ErrPrivateIP
	}
	if peerIP.IsLinkLocalUnicast() && !selfIP.IsLinkLocalUnicast() {
		return ErrLinkLocalIP
	}
	return nil
}
