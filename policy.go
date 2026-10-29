package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// alwaysDenied are ranges that are never part of the customer network to scan:
// the tunnel host itself ("this network", loopback) and cloud metadata services.
// Link-local, unspecified and multicast addresses are denied in allowed().
var alwaysDenied = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fd00:ec2::254/128"), // AWS metadata (IPv6)
}

// destinationPolicy is the SOCKS5 rule set of the tunnel. It allows only CONNECT,
// and never to the tunnel host itself (loopback, unspecified) or to link-local
// addresses (cloud metadata). Private ranges stay allowed: reaching the customer
// network is the purpose of the tunnel. -allow limits the destinations to the
// given ranges, -deny removes ranges.
type destinationPolicy struct {
	allow []netip.Prefix
	deny  []netip.Prefix
}

var _ socks5.RuleSet = (*destinationPolicy)(nil)

func newDestinationPolicy(allow, deny []string) (*destinationPolicy, error) {
	allowPrefixes, err := parsePrefixes(allow)
	if err != nil {
		return nil, fmt.Errorf("invalid -allow: %w", err)
	}
	denyPrefixes, err := parsePrefixes(deny)
	if err != nil {
		return nil, fmt.Errorf("invalid -deny: %w", err)
	}
	return &destinationPolicy{allow: allowPrefixes, deny: denyPrefixes}, nil
}

// parsePrefixes parses IPs and CIDRs.
func parsePrefixes(values []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, err
			}
			if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, err
		}
		addr = addr.Unmap().WithZone("")
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
}

// Allow implements socks5.RuleSet. The server resolves a host name once before
// the rule and connects to that address, so the checked address is the one dialed.
func (p *destinationPolicy) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if req.Command != statute.CommandConnect || req.DestAddr == nil {
		return ctx, false
	}
	addr, ok := netip.AddrFromSlice(req.DestAddr.IP)
	if !ok {
		return ctx, false
	}
	return ctx, p.allowed(addr)
}

func (p *destinationPolicy) allowed(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, prefix := range alwaysDenied {
		if prefix.Contains(addr) {
			return false
		}
	}
	for _, prefix := range p.deny {
		if prefix.Contains(addr) {
			return false
		}
	}
	if len(p.allow) == 0 {
		return true
	}
	for _, prefix := range p.allow {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// newSocksServer returns the tunnel SOCKS5 server with the destination policy.
func newSocksServer(policy *destinationPolicy, credentials socks5.CredentialStore) *socks5.Server {
	return socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(logger)),
		socks5.WithCredential(credentials),
		socks5.WithRule(policy),
	)
}
