// Package netutil provides IP address and CIDR validation, masking, and normalization
// conforming to Cloudflare IP List API constraints.
package netutil

import (
	"net/netip"
	"strings"
)

const (
	minIPv4PrefixBits = 16
	maxIPv4PrefixBits = 32
	minIPv6PrefixBits = 48
	maxIPv6PrefixBits = 64
	ipv6DefaultMask   = 64
)

// NormalizeIP validates an incoming CrowdSec decision scope and value,
// converting single IPv6 addresses into standard /64 prefixes and canonicalizing CIDR representations.
func NormalizeIP(scope, value string) (string, bool) {
	trimmedVal := strings.TrimSpace(value)
	if trimmedVal == "" {
		return "", false
	}

	if strings.EqualFold(scope, "Ip") {
		return normalizeSingleIP(trimmedVal)
	}

	if strings.EqualFold(scope, "Range") {
		return normalizeCIDR(trimmedVal)
	}

	return "", false
}

func normalizeSingleIP(val string) (string, bool) {
	addr, err := netip.ParseAddr(val)
	if err != nil {
		return "", false
	}

	if addr.Is4() {
		return addr.String(), true
	}

	return netip.PrefixFrom(addr, ipv6DefaultMask).Masked().String(), true
}

func normalizeCIDR(val string) (string, bool) {
	prefix, err := netip.ParsePrefix(val)
	if err != nil {
		return "", false
	}

	masked := prefix.Masked()
	bits := masked.Bits()

	if masked.Addr().Is4() {
		if bits >= minIPv4PrefixBits && bits <= maxIPv4PrefixBits {
			return masked.String(), true
		}
		return "", false
	}

	if bits >= minIPv6PrefixBits && bits <= maxIPv6PrefixBits {
		return masked.String(), true
	}
	return "", false
}
