package singbox

import (
	"bufio"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"

	pub "github.com/goose-network/goose-plugin-api"
)

// fakeStackDialer is a pub.StackDialer that records dials and returns a
// net.Pipe connection, so a test observes the bytes a sing-box proxy pushes
// through the engine stack with no real socket. onConn, when set, runs on
// the pipe's peer end and plays the server on the other side.
type fakeStackDialer struct {
	mu       sync.Mutex
	dials    []string
	networks []string
	onConn   func(net.Conn)
}

func (f *fakeStackDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, address)
	f.networks = append(f.networks, network)
	f.mu.Unlock()
	c1, c2 := net.Pipe()
	if f.onConn != nil {
		go f.onConn(c2)
	} else {
		go func() {
			<-ctx.Done()
			_ = c2.Close()
		}()
	}
	return c1, nil
}

// serveSocks5NoAuth completes a no-auth SOCKS5 handshake on conn's server
// side (greeting → method 0, CONNECT → success) and then parks until the
// peer closes, so a sing-box socks outbound finishes its dial over a pipe
// the engine stack handed back.
func serveSocks5NoAuth(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 5 {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, head[1])); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil { // no-auth
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
		return
	}
	var addrLen int
	switch req[3] {
	case 1:
		addrLen = 4
	case 4:
		addrLen = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		addrLen = int(l[0])
	default:
		return
	}
	if _, err := io.ReadFull(br, make([]byte, addrLen+2)); err != nil {
		return
	}
	// Success reply, BND.ADDR 0.0.0.0:0.
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, conn)
}

// TestStackNetwork verifies sing's family-specific network names collapse
// onto the engine stack's tcp/udp contract.
func TestStackNetwork(t *testing.T) {
	for in, want := range map[string]string{
		"tcp": "tcp", "tcp4": "tcp", "tcp6": "tcp",
		"udp": "udp", "udp4": "udp", "udp6": "udp",
	} {
		if got := stackNetwork(in); got != want {
			t.Errorf("stackNetwork(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestSocksaddrTarget verifies the destination rendering: FQDNs lose
// sing's trailing dot, plain addresses pass through.
func TestSocksaddrTarget(t *testing.T) {
	if got := socksaddrTarget(M.ParseSocksaddr("example.com.:443")); got != "example.com:443" {
		t.Errorf("fqdn target = %q", got)
	}
	if got := socksaddrTarget(M.ParseSocksaddr("10.9.8.7:1080")); got != "10.9.8.7:1080" {
		t.Errorf("ip target = %q", got)
	}
}

// TestSetDetour verifies the promoted-field detour setter across the
// conversion shapes: a direct DialerOptions embed (socks), a one-deep
// embed (snell, via AbstractSnellOutboundOptions), a native-options decode
// (shadowtls), and a type without DialerOptions reporting failure.
func TestSetDetour(t *testing.T) {
	const tag = "goose-test-detour"

	socksOpts, err := convertMapping("socks", map[string]any{"type": "socks5", "server": "10.9.8.7", "port": 1080})
	if err != nil {
		t.Fatalf("convert socks: %v", err)
	}
	if !setDetour(socksOpts, tag) {
		t.Fatal("setDetour(socks) reported failure")
	}
	if socksOpts.(*option.SOCKSOutboundOptions).Detour != tag {
		t.Errorf("socks Detour = %q", socksOpts.(*option.SOCKSOutboundOptions).Detour)
	}

	snellOpts, err := convertMapping("snell", map[string]any{"type": "snell", "server": "10.9.8.7", "port": 1080, "psk": "x", "version": 4})
	if err != nil {
		t.Fatalf("convert snell: %v", err)
	}
	if !setDetour(snellOpts, tag) {
		t.Fatal("setDetour(snell) reported failure")
	}

	shadowOpts, err := convertMapping("shadowtls", map[string]any{"type": "shadowtls", "options": map[string]any{"server": "10.9.8.7", "server_port": 443, "version": 3, "tls": map[string]any{"enabled": true, "server_name": "example.com"}}})
	if err != nil {
		t.Fatalf("convert shadowtls: %v", err)
	}
	if !setDetour(shadowOpts, tag) {
		t.Fatal("setDetour(shadowtls) reported failure")
	}

	if setDetour(&option.DirectOutboundOptions{}, tag) {
		// DirectOutboundOptions DOES embed DialerOptions; use a type that
		// truly lacks it instead.
		t.Log("direct options do carry DialerOptions")
	}
	if setDetour(&struct{ Detour int }{Detour: 0}, tag) {
		t.Fatal("setDetour succeeded on a struct with no string Detour field")
	}
	if setDetour(option.DirectOutboundOptions{}, tag) {
		t.Fatal("setDetour succeeded on a non-pointer value")
	}
}

// storeStack publishes a stack dialer in the engine-stack slot for the
// duration of one test.
func storeStack(t *testing.T, sd pub.StackDialer) {
	t.Helper()
	engineStackDialer.Store(&sd)
	t.Cleanup(func() { engineStackDialer.Store(nil) })
}

// TestEngineStackOutboundDials verifies the bridge outbound itself: a dial
// is a stack dial to the same destination, and a domain destination is
// passed to the stack unresolved (the engine stack resolves it).
func TestEngineStackOutboundDials(t *testing.T) {
	fs := &fakeStackDialer{}
	storeStack(t, fs)

	o := &engineStackOutbound{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := o.DialContext(ctx, "tcp", M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	_ = conn.Close()

	fs.mu.Lock()
	dials, networks := append([]string{}, fs.dials...), append([]string{}, fs.networks...)
	fs.mu.Unlock()
	if len(dials) != 1 || dials[0] != "example.com:443" {
		t.Fatalf("engine stack dialed %v, want [example.com:443]", dials)
	}
	if len(networks) != 1 || networks[0] != "tcp" {
		t.Fatalf("engine stack networks = %v, want [tcp]", networks)
	}
}

// TestEngineStackOutboundListenPacketRefusedOnNonPacketConn verifies the
// packet path fails loudly when the stack returns a stream, rather than
// handing sing-box a conn that panics on a PacketConn assertion.
func TestEngineStackOutboundListenPacketRefusedOnNonPacketConn(t *testing.T) {
	fs := &fakeStackDialer{}
	storeStack(t, fs)

	o := &engineStackOutbound{}
	if _, err := o.ListenPacket(context.Background(), M.ParseSocksaddr("10.9.8.7:443")); err == nil {
		t.Fatal("ListenPacket over a non-packet conn unexpectedly succeeded")
	}
}

// TestOutboundFactoryConsumesStackDialer verifies the factory
// type-asserts the engine-injected stack dialer out of the config map.
func TestOutboundFactoryConsumesStackDialer(t *testing.T) {
	factory, ok := pub.Lookup("singbox-socks")
	if !ok {
		t.Fatal("singbox-socks not registered")
	}
	base := map[string]any{
		"id":    "stack-1",
		"proxy": map[string]any{"type": "socks5", "server": "10.9.8.7", "port": 1080},
	}
	o, err := factory(base)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if o.(*Outbound).stack != nil {
		t.Fatal("stack dialer present without injection")
	}

	withStack := map[string]any{
		"id":      "stack-2",
		"proxy":   base["proxy"],
		"_dialer": &fakeStackDialer{},
	}
	o, err = factory(withStack)
	if err != nil {
		t.Fatalf("factory (with stack): %v", err)
	}
	if o.(*Outbound).stack == nil {
		t.Fatal("injected stack dialer not consumed")
	}
}

// TestOutboundDialsThroughEngineStack is the behavioral proof: a dial
// through a singbox-socks outbound must reach the proxy's server via the
// engine-injected stack dialer. The fake stack hands back a pipe whose
// peer completes the SOCKS5 handshake, so the dial succeeding at all
// proves the proxy's greeting and CONNECT bytes traversed the detour
// bridge and the engine stack — no socket sing-box owns is ever opened.
func TestOutboundDialsThroughEngineStack(t *testing.T) {
	fs := &fakeStackDialer{onConn: serveSocks5NoAuth}
	factory, ok := pub.Lookup("singbox-socks")
	if !ok {
		t.Fatal("singbox-socks not registered")
	}
	o, err := factory(map[string]any{
		"id": "stack-dial",
		"proxy": map[string]any{
			"type":   "socks5",
			"name":   "stack-dial-test",
			"server": "10.9.8.7",
			"port":   1080,
		},
		"_dialer": fs,
	})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := o.DialContext(ctx, pub.NetworkTCP, "example.com:80")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// The stack must have been consulted exactly once, for the proxy's own
	// server address, over TCP.
	fs.mu.Lock()
	dials, networks := append([]string{}, fs.dials...), append([]string{}, fs.networks...)
	fs.mu.Unlock()
	if len(dials) != 1 {
		t.Fatalf("engine stack dialed %d times, want 1: %v", len(dials), dials)
	}
	if dials[0] != "10.9.8.7:1080" {
		t.Fatalf("engine stack dialed %q, want the proxy server 10.9.8.7:1080", dials[0])
	}
	if len(networks) != 1 || networks[0] != "tcp" {
		t.Fatalf("engine stack networks = %v, want [tcp]", networks)
	}
}
