package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"

	"golang.org/x/net/proxy"
)

func TestDestinationPolicyAllowed(t *testing.T) {
	policy, err := newDestinationPolicy(nil, []string{"10.9.0.0/16", "192.168.50.7"})
	if err != nil {
		t.Fatal(err)
	}
	denied := []string{
		"127.0.0.1", "127.8.8.8", "0.0.0.0", "0.1.2.3", "::1", "::", "::ffff:127.0.0.1", "::ffff:0.0.0.0",
		"169.254.169.254", "::ffff:169.254.169.254", "fe80::1", "fe80::1%eth0", "fd00:ec2::254", "224.0.0.1", "ff02::1",
		"10.9.1.1", "192.168.50.7", "::ffff:10.9.1.1",
	}
	for _, a := range denied {
		if policy.allowed(netip.MustParseAddr(a)) {
			t.Errorf("%s allowed, want denied", a)
		}
	}
	// the customer network (private ranges) and public hosts stay reachable
	for _, a := range []string{"10.0.0.5", "172.16.3.4", "192.168.1.10", "100.64.1.1", "fd12:3456::1", "8.8.8.8", "::ffff:10.0.0.5"} {
		if !policy.allowed(netip.MustParseAddr(a)) {
			t.Errorf("%s denied, want allowed", a)
		}
	}

	scoped, err := newDestinationPolicy([]string{"10.0.0.0/8", "::ffff:192.168.1.0/120"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for a, want := range map[string]bool{"10.1.2.3": true, "192.168.1.9": true, "192.168.2.1": false, "8.8.8.8": false, "127.0.0.1": false} {
		if got := scoped.allowed(netip.MustParseAddr(a)); got != want {
			t.Errorf("scoped %s = %v, want %v", a, got, want)
		}
	}

	if _, err := newDestinationPolicy([]string{"not-a-cidr"}, nil); err == nil {
		t.Error("invalid -allow accepted")
	}
}

func startTestProxy(t *testing.T) string {
	t.Helper()
	policy, err := newDestinationPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := newSocksServer(policy, &credentialStore{user: "pdcp", password: "key"})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = server.Serve(listener) }()
	return listener.Addr().String()
}

// TestSocksDeniesTunnelHostLoopback replays the finding: through the tunnel a
// CONNECT to the tunnel host's loopback reached a loopback-only service.
func TestSocksDeniesTunnelHostLoopback(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("loopback-only service reached through the proxy (Host %s)", r.Host)
		_, _ = io.WriteString(w, "INTERNAL-ONLY-SECRET")
	}))
	defer internal.Close()
	port := strconv.Itoa(internal.Listener.Addr().(*net.TCPAddr).Port)

	dialer, err := proxy.SOCKS5("tcp", startTestProxy(t), &proxy.Auth{User: "pdcp", Password: "key"}, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "localhost", "::ffff:127.0.0.1", "::1", "0.0.0.0", "::", "127.1.2.3"} {
		conn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
		if err == nil {
			_ = conn.Close()
			t.Errorf("CONNECT to %s allowed", host)
		}
	}
}

// TestSocksDeniesBindAndAssociate sends raw BIND and UDP ASSOCIATE requests.
func TestSocksDeniesBindAndAssociate(t *testing.T) {
	addr := startTestProxy(t)
	for _, cmd := range []byte{0x02, 0x03} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		r := bufio.NewReader(conn)
		// greeting with username/password auth
		_, _ = conn.Write([]byte{0x05, 0x01, 0x02})
		reply := make([]byte, 2)
		if _, err := io.ReadFull(r, reply); err != nil || reply[1] != 0x02 {
			t.Fatalf("greeting reply %v %v", reply, err)
		}
		_, _ = conn.Write(append(append([]byte{0x01, 4}, "pdcp"...), append([]byte{3}, "key"...)...))
		if _, err := io.ReadFull(r, reply); err != nil || reply[1] != 0x00 {
			t.Fatalf("auth reply %v %v", reply, err)
		}
		// request to 8.8.8.8:53
		_, _ = conn.Write([]byte{0x05, cmd, 0x00, 0x01, 8, 8, 8, 8, 0, 53})
		resp := make([]byte, 2)
		if _, err := io.ReadFull(r, resp); err != nil {
			t.Fatalf("command %#x: %v", cmd, err)
		}
		if resp[1] != 0x02 { // connection not allowed by ruleset
			t.Errorf("command %#x: reply %#x, want 0x02", cmd, resp[1])
		}
		_ = conn.Close()
	}
}

// TestSocksAllowsCustomerNetwork checks that a CONNECT to a non-loopback address
// of this host (a stand-in for a customer network host) still works.
func TestSocksAllowsCustomerNetwork(t *testing.T) {
	var lanIP string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {
			lanIP = ipnet.IP.String()
			break
		}
	}
	if lanIP == "" {
		t.Skip("no non-loopback IPv4 address on this host")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(lanIP, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", lanIP, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "customer") })}
	go func() { _ = srv.Serve(listener) }()
	defer func() { _ = srv.Close() }()

	dialer, err := proxy.SOCKS5("tcp", startTestProxy(t), &proxy.Auth{User: "pdcp", Password: "key"}, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		t.Fatal("socks5 dialer does not support DialContext")
	}
	client := &http.Client{Transport: &http.Transport{DialContext: contextDialer.DialContext}}
	resp, err := client.Get("http://" + listener.Addr().String() + "/")
	if err != nil {
		t.Fatalf("customer network host not reachable: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "customer" {
		t.Fatalf("body %q", body)
	}
}
