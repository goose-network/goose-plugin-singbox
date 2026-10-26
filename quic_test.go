//go:build with_quic

package singbox

import (
	"testing"

	"github.com/sagernet/sing-box/option"

	pub "github.com/goose-network/goose-plugin-api"
)

// TestProtocolOfQuicTypes: with the with_quic tag the QUIC trio is dialable,
// in both mihomo (Clash YAML / V2Ray link) and native spellings.
func TestProtocolOfQuicTypes(t *testing.T) {
	for _, typ := range []string{"hysteria", "hysteria2", "tuic"} {
		if !quicSupported(typ) {
			t.Fatalf("quicSupported(%q) = false with with_quic", typ)
		}
		if p, ok := ProtocolOf(map[string]any{"type": typ, "server": "10.0.0.1", "port": 443}); !ok || p != "singbox-"+typ {
			t.Fatalf("%s: ProtocolOf = %q ok=%v", typ, p, ok)
		}
		if _, ok := pub.Lookup("singbox-" + typ); !ok {
			t.Fatalf("protocol singbox-%s not registered", typ)
		}
	}
}

// TestConvertQuicMapping checks the mihomo field mapping for each QUIC type.
func TestConvertQuicMapping(t *testing.T) {
	cases := []struct {
		sbType string
		m      map[string]any
		check  func(t *testing.T, opts any)
	}{
		{"hysteria", map[string]any{"server": "10.0.0.1", "port": 443, "auth-str": "sekret", "obfs": "xplus", "up": "100 Mbps", "down": "50 Mbps", "sni": "h.example"}, func(t *testing.T, opts any) {
			o := opts.(*option.HysteriaOutboundOptions)
			if o.Server != "10.0.0.1" || o.ServerPort != 443 || o.AuthString != "sekret" || o.Obfs != "xplus" {
				t.Fatalf("hysteria opts = %+v", o)
			}
			if o.Up == nil || o.Up.Value() != 100*125000 || o.Down == nil || o.Down.Value() != 50*125000 {
				t.Fatalf("hysteria bandwidth up=%v down=%v", o.Up, o.Down)
			}
			if o.TLS == nil || !o.TLS.Enabled || o.TLS.ServerName != "h.example" {
				t.Fatalf("hysteria tls = %+v", o.TLS)
			}
		}},
		{"hysteria", map[string]any{"server": "10.0.0.2", "port": 443, "up-speed": 20, "down-speed": 40}, func(t *testing.T, opts any) {
			o := opts.(*option.HysteriaOutboundOptions)
			if o.UpMbps != 20 || o.DownMbps != 40 {
				t.Fatalf("hysteria mbps opts = %+v", o)
			}
		}},
		{"hysteria2", map[string]any{"server": "10.0.0.3", "port": 443, "password": "pw", "obfs": "salamander", "obfs-password": "obfspw", "up": "30 Mbps", "sni": "h2.example"}, func(t *testing.T, opts any) {
			o := opts.(*option.Hysteria2OutboundOptions)
			if o.Password != "pw" || o.UpMbps != 30 {
				t.Fatalf("hysteria2 opts = %+v", o)
			}
			if o.Obfs == nil || o.Obfs.Type != "salamander" || o.Obfs.Password != "obfspw" {
				t.Fatalf("hysteria2 obfs = %+v", o.Obfs)
			}
			if o.TLS == nil || !o.TLS.Enabled || o.TLS.ServerName != "h2.example" {
				t.Fatalf("hysteria2 tls = %+v", o.TLS)
			}
		}},
		{"tuic", map[string]any{"server": "10.0.0.4", "port": 443, "uuid": "12345678-1234-1234-1234-123456789012", "password": "pw", "congestion-controller": "bbr", "udp-relay-mode": "quic", "reduce-rtt": true, "heartbeat-interval": 10, "sni": "t.example"}, func(t *testing.T, opts any) {
			o := opts.(*option.TUICOutboundOptions)
			if o.UUID != "12345678-1234-1234-1234-123456789012" || o.Password != "pw" || o.CongestionControl != "bbr" || o.UDPRelayMode != "quic" || !o.ZeroRTTHandshake {
				t.Fatalf("tuic opts = %+v", o)
			}
			if o.Heartbeat != 10_000_000_000 {
				t.Fatalf("tuic heartbeat = %v", o.Heartbeat)
			}
			if o.TLS == nil || !o.TLS.Enabled || o.TLS.ServerName != "t.example" {
				t.Fatalf("tuic tls = %+v", o.TLS)
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
}

// TestConvertQuicNativeOptions checks the native sing-box options dialect
// (raw object under "options") for the QUIC types.
func TestConvertQuicNativeOptions(t *testing.T) {
	opts, err := convertMapping("hysteria2", map[string]any{"type": "hysteria2", "password": "ignored", "options": map[string]any{
		"server": "hy2.example.com", "server_port": 8443.0,
		"password": "nativepw", "up_mbps": 60, "down_mbps": 120,
		"obfs":         map[string]any{"type": "salamander", "password": "obfspw"},
		"server_ports": []any{"20000:30000"},
		"tls":          map[string]any{"enabled": true, "server_name": "hy2.example.com", "insecure": true},
	}})
	if err != nil {
		t.Fatalf("convertMapping: %v", err)
	}
	o := opts.(*option.Hysteria2OutboundOptions)
	if o.Server != "hy2.example.com" || o.ServerPort != 8443 || o.Password != "nativepw" {
		t.Fatalf("hysteria2 native opts = %+v", o)
	}
	if o.UpMbps != 60 || o.DownMbps != 120 {
		t.Fatalf("hysteria2 native mbps = %+v", o)
	}
	if o.Obfs == nil || o.Obfs.Type != "salamander" || o.Obfs.Password != "obfspw" {
		t.Fatalf("hysteria2 native obfs = %+v", o.Obfs)
	}
	if len(o.ServerPorts) != 1 || o.ServerPorts[0] != "20000:30000" {
		t.Fatalf("hysteria2 native server_ports = %v", o.ServerPorts)
	}
	if o.TLS == nil || !o.TLS.Enabled || !o.TLS.Insecure || o.TLS.ServerName != "hy2.example.com" {
		t.Fatalf("hysteria2 native tls = %+v", o.TLS)
	}
}
