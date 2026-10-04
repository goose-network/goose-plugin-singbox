package singbox

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"

	pub "github.com/goose-network/goose-plugin-api"
)

// TestParseSubscriptionClashYAML verifies the Clash YAML path: a `proxies:`
// list is parsed into mappings with the expected goose protocol names.
func TestParseSubscriptionClashYAML(t *testing.T) {
	body := []byte(`
proxies:
  - name: "socks-one"
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: "vmess-one"
    type: vmess
    server: 127.0.0.1
    port: 443
    uuid: 12345678-1234-1234-1234-123456789012
    alterId: 0
    cipher: auto
`)
	mappings, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("want 2 mappings, got %d: %+v", len(mappings), mappings)
	}
	if p, ok := ProtocolOf(mappings[0]); !ok || p != "singbox-socks" {
		t.Fatalf("first mapping protocol = %q ok=%v", p, ok)
	}
	if p, ok := ProtocolOf(mappings[1]); !ok || p != "singbox-vmess" {
		t.Fatalf("second mapping protocol = %q ok=%v", p, ok)
	}
}

// TestParseSubscriptionV2RayLinks verifies the V2Ray-link-list path, both
// plain and base64-encoded.
func TestParseSubscriptionV2RayLinks(t *testing.T) {
	lines := []string{
		"socks5://127.0.0.1:1080#sock-a",
		"trojan://pass@example.com:443?sni=example.com#tro-a",
	}
	for name, body := range map[string][]byte{
		"plain":  []byte(strings.Join(lines, "\n")),
		"base64": []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))),
	} {
		mappings, err := ParseSubscription(body)
		if err != nil {
			t.Fatalf("%s: ParseSubscription: %v", name, err)
		}
		if len(mappings) != 2 {
			t.Fatalf("%s: want 2 mappings, got %d: %+v", name, len(mappings), mappings)
		}
		if p, ok := ProtocolOf(mappings[0]); !ok || p != "singbox-socks" {
			t.Fatalf("%s: first mapping protocol = %q ok=%v", name, p, ok)
		}
		if p, ok := ProtocolOf(mappings[1]); !ok || p != "singbox-trojan" {
			t.Fatalf("%s: second mapping protocol = %q ok=%v", name, p, ok)
		}
	}
}

// TestParseSubscriptionSkipsGroups verifies group/special types are skipped.
func TestParseSubscriptionSkipsGroups(t *testing.T) {
	body := []byte(`
proxies:
  - name: "a"
    type: socks5
    server: 127.0.0.1
    port: 1080
  - name: "wg"
    type: wireguard
    server: 127.0.0.1
    port: 51820
proxy-groups:
  - name: "g"
    type: select
    proxies: ["a"]
`)
	mappings, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	// wireguard has no always-compiled sing-box counterpart; the group is
	// never a proxy mapping at all. Only the socks5 entry survives.
	n := 0
	for _, m := range mappings {
		if _, ok := ProtocolOf(m); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want 1 dialable mapping, got %d: %+v", n, mappings)
	}
}

// TestConvertMapping checks the field mapping for each sing-box type the
// plugin claims to support: every supported type must convert without error
// and carry the server address.
func TestConvertMapping(t *testing.T) {
	uuid := "12345678-1234-1234-1234-123456789012"
	cases := []struct {
		sbType string
		m      map[string]any
		check  func(t *testing.T, opts any)
	}{
		{"socks", map[string]any{"server": "10.0.0.1", "port": 1080, "username": "u", "password": "p"}, func(t *testing.T, opts any) {
			o := opts.(*option.SOCKSOutboundOptions)
			if o.Server != "10.0.0.1" || o.ServerPort != 1080 || o.Username != "u" || o.Password != "p" {
				t.Fatalf("socks opts = %+v", o)
			}
		}},
		{"http", map[string]any{"server": "10.0.0.2", "port": 8080, "tls": true, "sni": "example.com"}, func(t *testing.T, opts any) {
			o := opts.(*option.HTTPOutboundOptions)
			if o.TLS == nil || !o.TLS.Enabled || o.TLS.ServerName != "example.com" {
				t.Fatalf("http tls = %+v", o.TLS)
			}
		}},
		{"shadowsocks", map[string]any{"server": "10.0.0.3", "port": 8388, "cipher": "aes-128-gcm", "password": "pw"}, func(t *testing.T, opts any) {
			o := opts.(*option.ShadowsocksOutboundOptions)
			if o.Method != "aes-128-gcm" || o.Password != "pw" || o.ServerPort != 8388 {
				t.Fatalf("ss opts = %+v", o)
			}
		}},
		{"vmess", map[string]any{"server": "10.0.0.4", "port": 443, "uuid": uuid, "cipher": "auto", "network": "ws", "ws-opts": map[string]any{"path": "/ws"}}, func(t *testing.T, opts any) {
			o := opts.(*option.VMessOutboundOptions)
			if o.UUID != uuid || o.Security != "auto" {
				t.Fatalf("vmess opts = %+v", o)
			}
			if o.Transport == nil || o.Transport.Type != "ws" || o.Transport.WebsocketOptions.Path != "/ws" {
				t.Fatalf("vmess transport = %+v", o.Transport)
			}
		}},
		{"vless", map[string]any{"server": "10.0.0.5", "port": 443, "uuid": uuid, "flow": "xtls-rprx-vision", "tls": true}, func(t *testing.T, opts any) {
			o := opts.(*option.VLESSOutboundOptions)
			if o.UUID != uuid || o.Flow != "xtls-rprx-vision" || o.TLS == nil {
				t.Fatalf("vless opts = %+v", o)
			}
		}},
		{"trojan", map[string]any{"server": "10.0.0.6", "port": 443, "password": "pw"}, func(t *testing.T, opts any) {
			o := opts.(*option.TrojanOutboundOptions)
			if o.Password != "pw" || o.TLS == nil || !o.TLS.Enabled {
				t.Fatalf("trojan opts = %+v", o)
			}
		}},
		{"snell", map[string]any{"server": "10.0.0.7", "port": 6160, "psk": "psk", "version": 4}, func(t *testing.T, opts any) {
			o := opts.(*option.SnellOutboundOptions)
			if o.Version != 4 || o.PSK != "psk" {
				t.Fatalf("snell opts = %+v", o)
			}
		}},
		{"ssh", map[string]any{"server": "10.0.0.8", "port": 22, "username": "u", "password": "p"}, func(t *testing.T, opts any) {
			o := opts.(*option.SSHOutboundOptions)
			if o.User != "u" || o.Password != "p" || o.ServerPort != 22 {
				t.Fatalf("ssh opts = %+v", o)
			}
		}},
		{"anytls", map[string]any{"server": "10.0.0.9", "port": 443, "password": "pw", "sni": "a.example"}, func(t *testing.T, opts any) {
			o := opts.(*option.AnyTLSOutboundOptions)
			if o.Password != "pw" || o.TLS == nil || o.TLS.ServerName != "a.example" {
				t.Fatalf("anytls opts = %+v", o)
			}
		}},
	}
	for _, tc := range cases {
		opts, err := convertMapping(tc.sbType, tc.m)
		if err != nil {
			t.Fatalf("%s: convertMapping: %v", tc.sbType, err)
		}
		tc.check(t, opts)
	}
	if _, err := convertMapping("nope", nil); err == nil {
		t.Fatal("unknown type should error")
	}
}

// TestProviderOutboundsEndToEnd runs the full provider flow against a local
// subscription server: fetch + parse + emit goose outbound configs whose
// factory can build a dialable sing-box outbound.
func TestProviderOutboundsEndToEnd(t *testing.T) {
	// A socks5 echo server the outbound will dial through.
	socksAddr, stopSocks := startTestSocks5(t)
	defer stopSocks()

	subBody := []byte(fmt.Sprintf("proxies:\n  - name: \"one\"\n    type: socks5\n    server: %s\n    port: %d\n",
		"127.0.0.1", mustPort(t, socksAddr)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(subBody)
	}))
	defer srv.Close()

	// The provider registered itself in init() as "singbox"; build it the
	// way the engine's manager would.
	factory, ok := pub.LookupProvider("singbox")
	if !ok {
		t.Fatal("provider singbox not registered")
	}
	prov, err := factory(map[string]any{"url": srv.URL})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if prov.Name() != "singbox" {
		t.Fatalf("Name = %q", prov.Name())
	}
	if prov.Watch() != nil {
		t.Fatal("Watch should be nil")
	}

	cfgs, err := prov.Outbounds(context.Background())
	if err != nil {
		t.Fatalf("Outbounds: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("want 1 outbound config, got %d: %+v", len(cfgs), cfgs)
	}
	oc := cfgs[0]
	if oc.Protocol != "singbox-socks" {
		t.Fatalf("protocol = %q", oc.Protocol)
	}
	if !strings.HasPrefix(oc.ID, "singbox-socks5-127.0.0.1:") {
		t.Fatalf("id = %q", oc.ID)
	}

	// The emitted config must be buildable by the registered outbound
	// factory and dialable through the socks5 server.
	build, ok := pub.Lookup(oc.Protocol)
	if !ok {
		t.Fatalf("outbound protocol %q not registered", oc.Protocol)
	}
	out, err := build(oc.Config)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if out.Protocol() != "singbox-socks" {
		t.Fatalf("out.Protocol = %q", out.Protocol())
	}
	if out.Address() == "" {
		t.Fatal("Address should carry the proxy server addr")
	}

	// Real dial through the singbox-built socks5 proxy to the echo upstream.
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()
	conn, err := out.DialContext(context.Background(), pub.NetworkTCP, echoAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
}

// --- test servers ---

// startEchoServer runs a TCP server echoing what it reads.
func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

// startTestSocks5 runs a minimal RFC1928 socks5 server (no-auth) that accepts
// the handshake and then echoes bytes, which is enough to prove the sing-box
// socks outbound completed a socks5 CONNECT.
func startTestSocks5(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveTestSocks5(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

// serveTestSocks5 performs the socks5 greeting + CONNECT handshake and then
// echoes (enough for the dial assertion).
func serveTestSocks5(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// greeting
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	// request: VER CMD RSV ATYP ...
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	var addrLen int
	switch req[3] {
	case 0x01:
		addrLen = 4
	case 0x04:
		addrLen = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		addrLen = int(l[0])
	}
	if addrLen > 0 {
		if _, err := io.ReadFull(c, make([]byte, addrLen+2)); err != nil {
			return
		}
	}
	// success reply with a zero bound address.
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_, _ = io.Copy(c, c)
}

// mustPort extracts the port from a host:port string for building YAML.
func mustPort(t *testing.T, hostPort string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("split %s: %v", hostPort, err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port %s: %v", portStr, err)
	}
	return port
}
