package singbox

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// TestParseSubscriptionSingboxJSON verifies the native sing-box config path:
// a full box config's `outbounds:` list is converted into mihomo-style
// mappings, with group/direct entries skipped and TLS/transport fields
// carried across.
func TestParseSubscriptionSingboxJSON(t *testing.T) {
	body := []byte(`{
  "log": {"level": "info"},
  "dns": {"servers": [{"tag": "local", "type": "local"}]},
  "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 1080}],
  "outbounds": [
    {"tag": "direct", "type": "direct"},
    {"tag": "select", "type": "selector", "outbounds": ["auto", "vmess-a"]},
    {"tag": "auto", "type": "urltest", "outbounds": ["vmess-a", "vless-b"]},
    {
      "tag": "vmess-a", "type": "vmess", "server": "v.example.com", "server_port": 443,
      "uuid": "12345678-1234-1234-1234-123456789012", "security": "auto", "alter_id": 2,
      "transport": {"type": "ws", "path": "/api", "max_early_data": 2560, "early_data_header_name": "Sec-WebSocket-Protocol"},
      "tls": {"enabled": true, "server_name": "v.example.com", "insecure": true, "alpn": ["h2", "http/1.1"]}
    },
    {
      "tag": "vless-b", "type": "vless", "server": "vl.example.com", "server_port": 8443,
      "uuid": "87654321-4321-4321-4321-210987654321", "flow": "",
      "transport": {"type": "ws", "headers": {"Host": "vl.example.com"}},
      "tls": {"enabled": true, "insecure": true}
    },
    {
      "tag": "trojan-c", "type": "trojan", "server": "t.example.com", "server_port": 443,
      "password": "pw", "tls": {"enabled": true, "server_name": "t.example.com"}
    },
    {"tag": "ss-d", "type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388, "method": "aes-256-gcm", "password": "sspw"}
  ],
  "route": {"rules": []}
}`)
	mappings, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(mappings) != 4 {
		t.Fatalf("want 4 dialable mappings, got %d: %+v", len(mappings), mappings)
	}

	byType := map[string]map[string]any{}
	for _, m := range mappings {
		byType[m["type"].(string)] = m
	}

	ss := byType["ss"]
	if ss["cipher"] != "aes-256-gcm" || ss["password"] != "sspw" || ss["port"] != 8388 {
		t.Fatalf("ss mapping = %+v", ss)
	}

	vm := byType["vmess"]
	if vm["server"] != "v.example.com" || vm["port"] != 443 {
		t.Fatalf("vmess mapping = %+v", vm)
	}
	if vm["uuid"] != "12345678-1234-1234-1234-123456789012" || vm["alterId"] != 2 {
		t.Fatalf("vmess mapping = %+v", vm)
	}
	if vm["tls"] != true || vm["sni"] != "v.example.com" || vm["skip-cert-verify"] != true {
		t.Fatalf("vmess tls mapping = %+v", vm)
	}
	if alpn, ok := vm["alpn"].([]string); !ok || len(alpn) != 2 || alpn[0] != "h2" {
		t.Fatalf("vmess alpn = %#v", vm["alpn"])
	}
	ws, ok := vm["ws-opts"].(map[string]any)
	if !ok || ws["path"] != "/api" || ws["max-early-data"] != 2560 {
		t.Fatalf("vmess ws-opts = %#v", vm["ws-opts"])
	}
	if ws["early-data-header-name"] != "Sec-WebSocket-Protocol" {
		t.Fatalf("vmess ws early-data header = %#v", ws)
	}

	vl := byType["vless"]
	if vl["uuid"] != "87654321-4321-4321-4321-210987654321" || vl["network"] != "ws" {
		t.Fatalf("vless mapping = %+v", vl)
	}
	ws, ok = vl["ws-opts"].(map[string]any)
	if !ok {
		t.Fatalf("vless ws-opts missing: %+v", vl)
	}
	if hdr, ok := ws["headers"].(map[string]any); !ok || hdr["Host"] != "vl.example.com" {
		t.Fatalf("vless ws headers = %#v", ws["headers"])
	}

	tr := byType["trojan"]
	if tr["password"] != "pw" || tr["tls"] != true || tr["sni"] != "t.example.com" {
		t.Fatalf("trojan mapping = %+v", tr)
	}

	// All four must claim a dialable goose protocol.
	for _, m := range mappings {
		if _, ok := ProtocolOf(m); !ok {
			t.Fatalf("mapping %q not dialable", m["type"])
		}
	}
}

// TestParseSubscriptionSingboxJSONMinimal checks a bare `outbounds:` array
// (the shape some subscription endpoints serve) parses too.
func TestParseSubscriptionSingboxJSONMinimal(t *testing.T) {
	body := []byte(`{"outbounds": [{"type": "socks", "tag": "s", "server": "127.0.0.1", "server_port": 1080, "version": "5"}]}`)
	mappings, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(mappings) != 1 {
		t.Fatalf("want 1 mapping, got %d: %+v", len(mappings), mappings)
	}
	if mappings[0]["type"] != "socks5" || mappings[0]["server"] != "127.0.0.1" || mappings[0]["port"] != 1080 {
		t.Fatalf("socks mapping = %+v", mappings[0])
	}
}

// TestSingboxToMappingSkipsNonDialable verifies group and abstract outbound
// types are excluded, and that the QUIC types pass through exactly when this
// build can dial them.
func TestSingboxToMappingSkipsNonDialable(t *testing.T) {
	for _, typ := range []string{"selector", "urltest", "direct", "dns", "block", "wireguard", "masque"} {
		if _, ok := singboxToMapping(map[string]any{"type": typ, "tag": typ}); ok {
			t.Fatalf("type %q should be skipped", typ)
		}
	}
	for _, typ := range []string{"hysteria", "hysteria2", "tuic"} {
		if _, ok := singboxToMapping(map[string]any{"type": typ, "tag": typ}); ok != quicSupported(typ) {
			t.Fatalf("type %q: singboxToMapping ok=%v, want %v (with_quic=%v)", typ, ok, quicSupported(typ), quicSupported(typ))
		}
	}
}

// TestProtocolOfGating checks the dialability gates: always-compiled types
// are accepted, QUIC types only in with_quic builds, unknown types never —
// in both the mihomo and the native (sing-box name) spellings.
func TestProtocolOfGating(t *testing.T) {
	for _, typ := range []string{"shadowtls", "tor"} {
		if p, ok := ProtocolOf(map[string]any{"type": typ, "server": "10.0.0.1", "port": 443}); !ok || p != "singbox-"+typ {
			t.Fatalf("%s: ProtocolOf = %q ok=%v", typ, p, ok)
		}
	}
	for _, typ := range []string{"hysteria", "hysteria2", "tuic"} {
		p, ok := ProtocolOf(map[string]any{"type": typ, "server": "10.0.0.1", "port": 443})
		if ok != quicSupported(typ) {
			t.Fatalf("%s: ProtocolOf = %q ok=%v, want ok=%v", typ, p, ok, quicSupported(typ))
		}
	}
	for _, typ := range []string{"ssr", "socks4", "wireguard", "mieru", "masque", ""} {
		if p, ok := ProtocolOf(map[string]any{"type": typ}); ok {
			t.Fatalf("type %q: ProtocolOf = %q, want rejected", typ, p)
		}
	}
}

// TestParseSubscriptionSingboxJSONNativeTypes verifies the native
// pass-through dialect: shadowtls/tor entries keep the raw sing-box object
// under "options" and still convert into typed options.
func TestParseSubscriptionSingboxJSONNativeTypes(t *testing.T) {
	body := []byte(`{"outbounds": [
	  {"tag": "stls", "type": "shadowtls", "server": "stls.example.com", "server_port": 443,
	   "version": 3, "password": "pw", "tls": {"enabled": true, "server_name": "cover.example.com"}},
	  {"tag": "tor-daemon", "type": "tor", "executable_path": "/usr/bin/tor", "torrc": {"SocksPort": "9050"}}
	]}`)
	mappings, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("want 2 mappings, got %d: %+v", len(mappings), mappings)
	}
	var stls, tor map[string]any
	for _, m := range mappings {
		switch m["type"] {
		case "shadowtls":
			stls = m
		case "tor":
			tor = m
		}
	}
	if stls == nil || tor == nil {
		t.Fatalf("missing mapping: stls=%v tor=%v", stls != nil, tor != nil)
	}
	// Common fields copy out for ServerKey/display...
	if stls["server"] != "stls.example.com" || stls["port"] != 443 || stls["name"] != "stls" {
		t.Fatalf("shadowtls mapping = %+v", stls)
	}
	// ...and the raw object rides along for exact conversion.
	opts, ok := stls["options"].(map[string]any)
	if !ok || opts["password"] != "pw" || opts["version"] != float64(3) {
		t.Fatalf("shadowtls options = %#v", stls["options"])
	}
	if _, ok := ProtocolOf(stls); !ok {
		t.Fatal("shadowtls not dialable")
	}
	if _, ok := ProtocolOf(tor); !ok {
		t.Fatal("tor not dialable")
	}
	converted, err := convertMapping("shadowtls", stls)
	if err != nil {
		t.Fatalf("convertMapping: %v", err)
	}
	o := converted.(*option.ShadowTLSOutboundOptions)
	if o.Server != "stls.example.com" || o.ServerPort != 443 || o.Version != 3 || o.Password != "pw" {
		t.Fatalf("shadowtls opts = %+v", o)
	}
	if o.TLS == nil || !o.TLS.Enabled || o.TLS.ServerName != "cover.example.com" {
		t.Fatalf("shadowtls tls = %+v", o.TLS)
	}
	// serverAddr reads either dialect; tor has no server address.
	if got := serverAddr(stls); got != "stls.example.com:443" {
		t.Fatalf("shadowtls serverAddr = %q", got)
	}
	if got := serverAddr(tor); got != "" {
		t.Fatalf("tor serverAddr = %q, want empty", got)
	}
}

// TestSingboxJSONEndToEndConvert converts the parsed mappings through
// convertMapping to prove the field mapping lands in sing-box option structs.
func TestSingboxJSONEndToEndConvert(t *testing.T) {
	body := []byte(`{"outbounds": [{
      "tag": "vm", "type": "vmess", "server": "vm.example.com", "server_port": 443,
      "uuid": "12345678-1234-1234-1234-123456789012", "alter_id": 2,
      "transport": {"type": "ws", "path": "/api"},
      "tls": {"enabled": true, "server_name": "vm.example.com", "insecure": true}
	}]}`)
	mappings, err := ParseSubscription(body)
	if err != nil {
		t.Fatalf("ParseSubscription: %v", err)
	}
	opts, err := convertMapping("vmess", mappings[0])
	if err != nil {
		t.Fatalf("convertMapping: %v", err)
	}
	// Verify via JSON round-trip: the option struct must carry the fields.
	b, err := json.Marshal(opts)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var flat map[string]any
	if err := json.Unmarshal(b, &flat); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if flat["server"] != "vm.example.com" {
		t.Fatalf("server = %v", flat["server"])
	}
	tls, ok := flat["tls"].(map[string]any)
	if !ok || tls["enabled"] != true || tls["server_name"] != "vm.example.com" {
		t.Fatalf("tls = %#v", flat["tls"])
	}
	tr, ok := flat["transport"].(map[string]any)
	if !ok || tr["type"] != "ws" || tr["path"] != "/api" {
		t.Fatalf("transport = %#v", flat["transport"])
	}
}
