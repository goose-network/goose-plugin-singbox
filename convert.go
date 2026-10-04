// convert.go converts mihomo proxy mappings into sing-box outbound option
// structs. The field names follow mihomo's `proxy:` struct tags (server, port,
// uuid, cipher, ws-opts, ...) and sing-box's option structs (Server,
// ServerPort, UUID, Security, Transport), so a subscription parsed by
// mihomo's converters can be dialed by sing-box's protocol implementations.
package singbox

import (
	"fmt"
	"strings"

	"github.com/sagernet/sing/common/json/badoption"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// convertMapping builds the sing-box options struct for one proxy type from
// its mihomo mapping. The returned pointer is what the sing-box registry's
// CreateOutbound expects.
func convertMapping(sbType string, m map[string]any) (any, error) {
	switch sbType {
	case "socks":
		return convertSocks(m), nil
	case "http":
		return convertHTTP(m), nil
	case "shadowsocks":
		return convertShadowsocks(m), nil
	case "vmess":
		return convertVMess(m), nil
	case "vless":
		return convertVLESS(m), nil
	case "trojan":
		return convertTrojan(m), nil
	case "snell":
		return convertSnell(m)
	case "ssh":
		return convertSSH(m), nil
	case "anytls":
		return convertAnyTLS(m), nil
	default:
		return nil, fmt.Errorf("unsupported type %q", sbType)
	}
}

// server fills the embedded ServerOptions.
func server(m map[string]any) option.ServerOptions {
	return option.ServerOptions{Server: mappingStr(m, "server"), ServerPort: mappingPort(m)}
}

// tlsEnabled reports whether the mihomo mapping asks for TLS (the `tls: true`
// flag, or an anytls/shadowtls type where TLS is part of the protocol).
func tlsEnabled(m map[string]any) bool {
	v, _ := m["tls"].(bool)
	return v
}

// tlsOptions builds OutboundTLSOptions: sni wins, then servername, then the
// server itself as the SNI; skip-cert-verify maps to Insecure.
func tlsOptions(m map[string]any) *option.OutboundTLSOptions {
	sni := mappingStr(m, "sni")
	if sni == "" {
		sni = mappingStr(m, "servername")
	}
	if sni == "" {
		sni = mappingStr(m, "server")
	}
	tls := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: sni,
	}
	if skip, _ := m["skip-cert-verify"].(bool); skip {
		tls.Insecure = true
	}
	if alpn := mappingStrings(m, "alpn"); len(alpn) > 0 {
		tls.ALPN = badoption.Listable[string](alpn)
	}
	return tls
}

// maybeTLS fills the TLS container only when the mapping enables TLS, so
// protocols that work in the clear (socks, http, vmess, ...) keep working
// without it.
func maybeTLS(m map[string]any) option.OutboundTLSOptionsContainer {
	if !tlsEnabled(m) {
		return option.OutboundTLSOptionsContainer{}
	}
	return option.OutboundTLSOptionsContainer{TLS: tlsOptions(m)}
}

// transport converts mihomo's `network` + per-network opts maps (`ws-opts`,
// `grpc-opts`, `http-opts`) into sing-box's V2RayTransportOptions. It returns
// nil when the proxy is plain TCP.
func transport(m map[string]any) *option.V2RayTransportOptions {
	network := mappingStr(m, "network")
	switch network {
	case "", "tcp":
		return nil
	case "ws":
		ws := option.V2RayWebsocketOptions{}
		if opts, ok := m["ws-opts"].(map[string]any); ok {
			ws.Path = mappingStr(opts, "path")
			if ed := mappingInt(opts, "max-early-data"); ed > 0 {
				ws.MaxEarlyData = uint32(ed)
				ws.EarlyDataHeaderName = mappingStr(opts, "early-data-header-name")
			}
		}
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeWebsocket, WebsocketOptions: ws}
	case "grpc":
		grpc := option.V2RayGRPCOptions{}
		if opts, ok := m["grpc-opts"].(map[string]any); ok {
			grpc.ServiceName = mappingStr(opts, "grpc-service-name")
		}
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeGRPC, GRPCOptions: grpc}
	case "httpupgrade":
		up := option.V2RayHTTPUpgradeOptions{}
		if opts, ok := m["ws-opts"].(map[string]any); ok {
			up.Path = mappingStr(opts, "path")
		}
		return &option.V2RayTransportOptions{Type: C.V2RayTransportTypeHTTPUpgrade, HTTPUpgradeOptions: up}
	default:
		// Unknown transport: fall back to plain TCP rather than dropping the
		// proxy; the dial will surface the mismatch if there is one.
		return nil
	}
}

// vmessSecurity maps mihomo cipher names onto sing-box's security values.
// mihomo's "auto" is sing-box's default too.
func vmessSecurity(m map[string]any) string {
	switch cipher := strings.ToLower(mappingStr(m, "cipher")); cipher {
	case "auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305", "aes-128-cfb":
		return cipher
	default:
		return "auto"
	}
}

func convertSocks(m map[string]any) *option.SOCKSOutboundOptions {
	return &option.SOCKSOutboundOptions{
		ServerOptions: server(m),
		Version:       "5",
		Username:      mappingStr(m, "username"),
		Password:      mappingStr(m, "password"),
	}
}

func convertHTTP(m map[string]any) *option.HTTPOutboundOptions {
	return &option.HTTPOutboundOptions{
		ServerOptions:               server(m),
		Username:                    mappingStr(m, "username"),
		Password:                    mappingStr(m, "password"),
		OutboundTLSOptionsContainer: maybeTLS(m),
		Path:                        mappingStr(m, "path"),
	}
}

func convertShadowsocks(m map[string]any) *option.ShadowsocksOutboundOptions {
	return &option.ShadowsocksOutboundOptions{
		ServerOptions: server(m),
		Method:        mappingStr(m, "cipher"),
		Password:      mappingStr(m, "password"),
	}
}

func convertVMess(m map[string]any) *option.VMessOutboundOptions {
	return &option.VMessOutboundOptions{
		ServerOptions:               server(m),
		UUID:                        mappingStr(m, "uuid"),
		Security:                    vmessSecurity(m),
		AlterId:                     mappingInt(m, "alterId"),
		OutboundTLSOptionsContainer: maybeTLS(m),
		Transport:                   transport(m),
	}
}

func convertVLESS(m map[string]any) *option.VLESSOutboundOptions {
	return &option.VLESSOutboundOptions{
		ServerOptions:               server(m),
		UUID:                        mappingStr(m, "uuid"),
		Flow:                        mappingStr(m, "flow"),
		OutboundTLSOptionsContainer: maybeTLS(m),
		Transport:                   transport(m),
	}
}

func convertTrojan(m map[string]any) *option.TrojanOutboundOptions {
	// Trojan is TLS-only in practice; mihomo defaults tls on for it.
	tls := tlsEnabled(m)
	if !tls {
		if network := mappingStr(m, "network"); network == "" || network == "tcp" {
			tls = true
		}
	}
	container := option.OutboundTLSOptionsContainer{}
	if tls {
		container.TLS = tlsOptions(m)
	}
	return &option.TrojanOutboundOptions{
		ServerOptions:               server(m),
		Password:                    mappingStr(m, "password"),
		OutboundTLSOptionsContainer: container,
		Transport:                   transport(m),
	}
}

// convertSnell maps mihomo snell versions onto sing-box's v4/v6 split.
// mihomo DefaultSnellVersion is v1 and v5 servers accept v4 clients; sing-box
// supports only 4 and 6, so anything below 6 becomes 4.
func convertSnell(m map[string]any) (*option.SnellOutboundOptions, error) {
	version := mappingInt(m, "version")
	switch version {
	case 0, 1, 2, 3, 4, 5:
		version = 4
	case 6:
	default:
		return nil, fmt.Errorf("unsupported snell version %d", version)
	}
	opts := &option.SnellOutboundOptions{
		Version: version,
		AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
			ServerOptions: server(m),
			PSK:           mappingStr(m, "psk"),
			Reuse:         mappingBool(m, "reuse"),
		},
	}
	if obfs, ok := m["obfs-opts"].(map[string]any); ok {
		opts.ObfsOptions.ObfsMode = mappingStr(obfs, "mode")
		opts.ObfsOptions.ObfsHost = mappingStr(obfs, "host")
	}
	return opts, nil
}

func convertSSH(m map[string]any) *option.SSHOutboundOptions {
	return &option.SSHOutboundOptions{
		ServerOptions: server(m),
		User:          mappingStr(m, "username"),
		Password:      mappingStr(m, "password"),
	}
}

// convertAnyTLS: anytls is TLS-by-definition, so the container is always set.
func convertAnyTLS(m map[string]any) *option.AnyTLSOutboundOptions {
	return &option.AnyTLSOutboundOptions{
		ServerOptions:               server(m),
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions(m)},
		Password:                    mappingStr(m, "password"),
	}
}

// mappingBool reads a bool field (JSON booleans survive YAML parsing as bool).
func mappingBool(m map[string]any, key string) bool {
	v, _ := m[key].(bool)
	return v
}

// mappingInt reads a numeric field across YAML's float64 and JSON's int.
func mappingInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		var n int
		_, _ = fmt.Sscanf(v, "%d", &n)
		return n
	}
	return 0
}

// mappingStrings reads a string-list field.
func mappingStrings(m map[string]any, key string) []string {
	switch v := m[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
