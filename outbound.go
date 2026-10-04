// outbound.go implements the goose outbound protocols "singbox-<type>" for
// the always-compiled sing-box proxy types. The factory converts a mihomo
// proxy mapping into sing-box outbound options, creates the outbound through
// sing-box's registry, and dials targets with a parsed Socksaddr.
package singbox

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	pub "github.com/goose-network/goose-plugin-api"
)

// supportedTypes are the sing-box outbound types this plugin exposes, all of
// which compile without sing-box build tags. QUIC protocols (hysteria,
// hysteria2, tuic) need with_quic and are skipped in subscriptions.
var supportedTypes = map[string]bool{
	"socks":       true,
	"http":        true,
	"shadowsocks": true,
	"vmess":       true,
	"vless":       true,
	"trojan":      true,
	"snell":       true,
	"ssh":         true,
	"anytls":      true,
}

// mihomoToSingboxType maps mihomo proxy type names to sing-box outbound
// types. Only entries where the wire protocol is actually the same are
// listed; the rest (ssr, hysteria, wireguard, mieru, ...) have no
// always-compiled sing-box counterpart and are skipped.
var mihomoToSingboxType = map[string]string{
	"socks5": "socks",
	"http":   "http",
	"ss":     "shadowsocks",
	"vmess":  "vmess",
	"vless":  "vless",
	"trojan": "trojan",
	"snell":  "snell",
	"ssh":    "ssh",
	"anytls": "anytls",
}

func init() {
	for typ := range supportedTypes {
		pub.Register("singbox-"+typ, newOutboundFactory(typ))
	}
}

// newOutboundFactory returns an OutboundFactory for one sing-box type.
func newOutboundFactory(typ string) pub.OutboundFactory {
	return func(cfg map[string]any) (pub.Outbound, error) {
		raw, ok := cfg["proxy"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("singbox %s outbound: missing proxy mapping", typ)
		}
		id, _ := cfg["id"].(string)
		return &Outbound{id: id, proto: "singbox-" + typ, mapping: raw}, nil
	}
}

// ProtocolOf maps a mihomo proxy mapping to its goose outbound protocol name
// ("singbox-<type>"). It returns ok=false for types this build cannot dial.
func ProtocolOf(m map[string]any) (string, bool) {
	typ, _ := m["type"].(string)
	if typ == "" {
		return "", false
	}
	sbType, ok := mihomoToSingboxType[typ]
	if !ok || !supportedTypes[sbType] {
		return "", false
	}
	return "singbox-" + sbType, true
}

// Outbound is a goose outbound backed by one sing-box outbound. The sing-box
// outbound object is built lazily on first dial: constructing a pool of
// hundreds of subscription proxies then costs no connections up front, and a
// mapping that fails to convert is reported at dial time instead of
// pool-build time (matching how the engine tolerates broken outbounds).
type Outbound struct {
	id      string
	proto   string
	mapping map[string]any

	once   sync.Once
	sb     adapter.Outbound
	addr   string
	buildE error
}

// ensure builds the sing-box outbound exactly once.
func (o *Outbound) ensure() error {
	o.once.Do(func() {
		ctx, err := getBoxContext()
		if err != nil {
			o.buildE = err
			return
		}
		sbType := strings.TrimPrefix(o.proto, "singbox-")
		opts, err := convertMapping(sbType, o.mapping)
		if err != nil {
			o.buildE = fmt.Errorf("singbox outbound: convert %s: %w", o.proto, err)
			return
		}
		sb, err := includeOutboundRegistry().CreateOutbound(ctx, nil, log.NewNOPFactory().NewLogger("outbound/"+sbType), o.id, sbType, opts)
		if err != nil {
			o.buildE = fmt.Errorf("singbox outbound: create %s: %w", o.proto, err)
			return
		}
		// Run the outbound's start stages so long-lived machinery (e.g. the
		// urltest history storage) is initialized, mirroring
		// outbound.Manager.Create's started path.
		for _, stage := range adapter.ListStartStages {
			if err := adapter.LegacyStart(sb, stage); err != nil {
				o.buildE = fmt.Errorf("singbox outbound: start %s: %w", o.proto, err)
				return
			}
		}
		o.sb = sb
		o.addr = serverAddr(o.mapping)
	})
	return o.buildE
}

func (o *Outbound) ID() string       { return o.id }
func (o *Outbound) Protocol() string { return o.proto }

// Address returns the proxy's server address (host:port), used for
// geo-location and metrics.
func (o *Outbound) Address() string {
	if err := o.ensure(); err != nil {
		return ""
	}
	return o.addr
}

func (o *Outbound) Location() *pub.Location { return nil }

func (o *Outbound) Stats() pub.OutboundStats { return pub.OutboundStats{} }

// DialContext dials the target through the sing-box outbound. The target is
// passed to the remote server as-is (a domain destination is resolved by the
// proxy server or the local DNS transport, not pre-resolved locally).
func (o *Outbound) DialContext(ctx context.Context, network pub.Network, target string) (net.Conn, error) {
	if err := o.ensure(); err != nil {
		return nil, err
	}
	netStr := N.NetworkTCP
	if network == pub.NetworkUDP {
		netStr = N.NetworkUDP
	}
	destination := M.ParseSocksaddr(target)
	if !destination.IsValid() {
		return nil, fmt.Errorf("singbox outbound: bad target %q", target)
	}
	conn, err := o.sb.DialContext(ctx, netStr, destination)
	if err != nil {
		return nil, fmt.Errorf("singbox outbound: dial %s via %s: %w", target, o.proto, err)
	}
	return conn, nil
}

// serverAddr renders host:port from the mapping.
func serverAddr(m map[string]any) string {
	host, _ := m["server"].(string)
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, fmt.Sprint(m["port"]))
}

// includeOutboundRegistry returns the outbound registry installed by
// include.Context, used to create outbounds. buildBoxContext populates
// boxOutboundRegistry in provider.go; the indirection keeps tests from
// depending on the context being built first.
var includeOutboundRegistry = func() adapter.OutboundRegistry {
	return boxOutboundRegistry
}

// mappingStr reads a string field from the mapping.
func mappingStr(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// mappingPort reads the port field as uint16.
func mappingPort(m map[string]any) uint16 {
	switch v := m["port"].(type) {
	case float64:
		return uint16(v)
	case int:
		return uint16(v)
	case string:
		n, _ := strconv.ParseUint(v, 10, 16)
		return uint16(n)
	}
	return 0
}
