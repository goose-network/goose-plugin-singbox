//go:build with_quic

// quic.go registers the sing-box outbound types that need the with_quic
// build tag (mirroring sing-box's own include/quic.go): hysteria, hysteria2
// and tuic, all QUIC-based. The protocols exist and subscriptions carry them
// only in with_quic builds; quic_stub.go provides the no-op counterparts
// otherwise, so the rest of the plugin compiles identically either way.
package singbox

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/sagernet/sing-box/option"

	pub "github.com/goose-network/goose-plugin-api"
)

// quicTypes are the sing-box outbound types gated behind with_quic.
var quicTypes = map[string]bool{
	"hysteria":  true,
	"hysteria2": true,
	"tuic":      true,
}

func init() {
	for typ := range quicTypes {
		pub.Register("singbox-"+typ, newOutboundFactory(typ))
	}
}

// quicSupported reports whether sbType is a QUIC outbound this build has.
func quicSupported(sbType string) bool { return quicTypes[sbType] }

// convertQuic dispatches the with_quic types' converters.
func convertQuic(sbType string, m map[string]any) (any, error) {
	switch sbType {
	case "hysteria":
		return convertHysteria(m)
	case "hysteria2":
		return convertHysteria2(m)
	case "tuic":
		return convertTUIC(m)
	default:
		return nil, fmt.Errorf("unsupported type %q", sbType)
	}
}

// networkBytes parses a mihomo bandwidth string ("100 Mbps", "50") into the
// byte-rate sing-box's up/down fields expect, using sing's own parser so the
// unit table matches. Unparseable values are dropped (bandwidth is a hint,
// not auth).
func networkBytes(s string) *byteformats.NetworkBytesCompat {
	if s == "" {
		return nil
	}
	v := &byteformats.NetworkBytesCompat{}
	if err := json.Unmarshal([]byte(strconv.Quote(s)), v); err != nil {
		return nil
	}
	return v
}

// mappingMbps reads a bandwidth field as Mbps. mihomo hysteria/hysteria2 use
// string values ("100 Mbps"); the leading number is the Mbps count
// sing-box's up_mbps/down_mbps fields take.
func mappingMbps(m map[string]any, key string) int {
	if v, ok := m[key].(string); ok {
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(v), "%d", &n)
		return n
	}
	return mappingInt(m, key)
}

// convertHysteria maps mihomo hysteria (v1) fields: auth-str/auth, obfs, and
// up/down — either the string form ("100 Mbps") or mihomo's int up-speed /
// down-speed. TLS is mandatory (sing-box rejects a hysteria outbound without
// it), so the container is always set.
func convertHysteria(m map[string]any) (*option.HysteriaOutboundOptions, error) {
	var native option.HysteriaOutboundOptions
	if ok, err := nativeOptions(m, &native); err != nil {
		return nil, err
	} else if ok {
		return &native, nil
	}
	return &option.HysteriaOutboundOptions{
		ServerOptions: server(m),
		Obfs:          mappingStr(m, "obfs"),
		Auth:          []byte(mappingStr(m, "auth")),
		AuthString:    mappingStr(m, "auth-str"),
		Up:            networkBytes(mappingStr(m, "up")),
		Down:          networkBytes(mappingStr(m, "down")),
		UpMbps:        mappingInt(m, "up-speed"),
		DownMbps:      mappingInt(m, "down-speed"),
		// TLS is part of the protocol, not an option.
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions(m)},
	}, nil
}

// convertHysteria2 maps mihomo hysteria2 fields: password, obfs +
// obfs-password (salamander), up/down. TLS is mandatory, so the container is
// always set.
func convertHysteria2(m map[string]any) (*option.Hysteria2OutboundOptions, error) {
	var native option.Hysteria2OutboundOptions
	if ok, err := nativeOptions(m, &native); err != nil {
		return nil, err
	} else if ok {
		return &native, nil
	}
	opts := &option.Hysteria2OutboundOptions{
		ServerOptions: server(m),
		Password:      mappingStr(m, "password"),
		UpMbps:        mappingMbps(m, "up"),
		DownMbps:      mappingMbps(m, "down"),
		// TLS is part of the protocol, not an option.
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions(m)},
	}
	if obfs := mappingStr(m, "obfs"); obfs != "" {
		opts.Obfs = &option.Hysteria2Obfs{Type: obfs, Password: mappingStr(m, "obfs-password")}
	}
	return opts, nil
}

// convertTUIC maps mihomo tuic fields: uuid/password, congestion-controller,
// udp-relay-mode, reduce-rtt, heartbeat-interval (seconds). The legacy token
// auth (tuic v4) has no sing-box counterpart and is ignored. TLS is
// mandatory, so the container is always set.
func convertTUIC(m map[string]any) (*option.TUICOutboundOptions, error) {
	var native option.TUICOutboundOptions
	if ok, err := nativeOptions(m, &native); err != nil {
		return nil, err
	} else if ok {
		return &native, nil
	}
	opts := &option.TUICOutboundOptions{
		ServerOptions:     server(m),
		UUID:              mappingStr(m, "uuid"),
		Password:          mappingStr(m, "password"),
		CongestionControl: mappingStr(m, "congestion-controller"),
		UDPRelayMode:      mappingStr(m, "udp-relay-mode"),
		ZeroRTTHandshake:  mappingBool(m, "reduce-rtt"),
		// TLS is part of the protocol, not an option.
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions(m)},
	}
	if hb := mappingInt(m, "heartbeat-interval"); hb > 0 {
		opts.Heartbeat = badoption.Duration(time.Duration(hb) * time.Second)
	}
	return opts, nil
}
