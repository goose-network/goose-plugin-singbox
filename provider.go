// Package singbox is the sing-box subscription provider plugin for the
// goose proxy-pool engine.
//
// It embeds github.com/sagernet/sing-box as a Go library and gives goose two
// things:
//
//   - a Provider ("singbox") that fetches a subscription URL and parses the
//     body with mihomo's converters (Clash YAML `proxies:` lists and
//     V2Ray-style link lists) into proxy mappings, then converts each
//     mapping into a sing-box outbound;
//   - an outbound protocol for the always-compiled sing-box proxy types,
//     registered under "singbox-<type>" (e.g. "singbox-vmess",
//     "singbox-trojan", "singbox-shadowsocks"), which dials by creating the
//     sing-box outbound via its registry and calling DialContext with a
//     parsed Socksaddr destination.
//
// # Why a shared sing-box context
//
// sing-box outbounds pull their dependencies (network manager, DNS
// transport manager, DNS router, connection manager) from a
// context.Context, mirroring box.New's construction order. One package-level
// context is built lazily and shared by every outbound the plugin creates:
// the DNS transport manager's "local" fallback makes domain server
// addresses resolve via the system resolver, and a shared outbound manager
// gives every outbound a common "direct" fallback. This is exactly what
// sing-box's own test suite does with its globalCtx.
//
// # Outbound config shape
//
// The provider stores the raw proxy mapping under cfg["proxy"], and the
// outbound factory converts it to sing-box options and creates the
// outbound lazily (on first dial, under a lock), so building a pool of
// hundreds of proxies costs no connections up front.
//
// # Provider config
//
//	{
//	  "url":    "https://example.com/sub",   // required
//	  "prefix": "singbox"                     // optional, outbound-id prefix
//	}
package singbox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/convert"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/sagernet/sing/service/pause"

	"github.com/sagernet/sing-box/adapter"
	boxEndpoint "github.com/sagernet/sing-box/adapter/endpoint"
	boxInbound "github.com/sagernet/sing-box/adapter/inbound"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/service"

	pub "github.com/goose-network/goose-plugin-api"
)

func init() {
	pub.RegisterProvider("singbox", NewProvider)
}

const (
	// fetchTimeout bounds one subscription download.
	fetchTimeout = 30 * time.Second
	// maxBodyBytes caps the subscription body so a hostile link cannot
	// exhaust engine memory.
	maxBodyBytes = 8 << 20
	// defaultPrefix is the outbound-id prefix when the config omits one.
	defaultPrefix = "singbox"
)

// Provider is a goose outbound provider backed by a sing-box subscription.
type Provider struct {
	url    string
	prefix string
	client *http.Client
}

// NewProvider builds a singbox provider from config:
//
//	{"url":"https://...","prefix":"singbox"}
func NewProvider(cfg map[string]any) (pub.Provider, error) {
	u, _ := cfg["url"].(string)
	if u == "" {
		return nil, fmt.Errorf("singbox provider: missing url")
	}
	prefix, _ := cfg["prefix"].(string)
	if prefix == "" {
		prefix = defaultPrefix
	}
	return &Provider{
		url:    u,
		prefix: prefix,
		client: &http.Client{Timeout: fetchTimeout},
	}, nil
}

// Name identifies the plugin.
func (p *Provider) Name() string { return "singbox" }

// Watch is nil: the provider has no change signal of its own, so the engine
// falls back to periodic polling of Outbounds.
func (p *Provider) Watch() <-chan struct{} { return nil }

// Outbounds fetches the subscription and parses it into outbound configs.
func (p *Provider) Outbounds(ctx context.Context) ([]pub.OutboundConfig, error) {
	body, err := p.fetch(ctx)
	if err != nil {
		return nil, err
	}
	mappings, err := ParseSubscription(body)
	if err != nil {
		return nil, fmt.Errorf("singbox provider: parse %s: %w", p.url, err)
	}
	out := make([]pub.OutboundConfig, 0, len(mappings))
	seen := map[string]int{}
	for _, m := range mappings {
		proto, ok := ProtocolOf(m)
		if !ok {
			continue // type not supported by this build
		}
		id := fmt.Sprintf("%s-%s-%s", p.prefix, m["type"], ServerKey(m))
		seen[id]++
		if n := seen[id]; n > 1 {
			id = fmt.Sprintf("%s-%d", id, n)
		}
		out = append(out, pub.OutboundConfig{
			ID:       id,
			Protocol: proto,
			Config:   map[string]any{"id": id, "proxy": m},
		})
	}
	return out, nil
}

// fetch downloads the subscription body.
func (p *Provider) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, fmt.Errorf("singbox provider: bad url: %w", err)
	}
	res, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("singbox provider: fetch %s: %w", p.url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("singbox provider: %s: status %s", p.url, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("singbox provider: read %s: %w", p.url, err)
	}
	return body, nil
}

// ParseSubscription turns a subscription body into mihomo-style proxy
// mappings (the common representation the converter consumes). Clash YAML is
// tried first; anything else falls through to mihomo's V2Ray-style link
// converter (which also handles base64-encoded lists).
func ParseSubscription(body []byte) ([]map[string]any, error) {
	if mappings, ok := parseClashYAML(body); ok {
		return mappings, nil
	}
	return convert.ConvertsV2Ray(body)
}

// parseClashYAML extracts a Clash `proxies:` list. It returns ok=false when
// the body is not a Clash YAML config, letting the caller fall back to the
// link-list format.
func parseClashYAML(body []byte) ([]map[string]any, bool) {
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	raw, ok := doc["proxies"]
	if !ok {
		return nil, false
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, m)
	}
	return out, len(out) > 0
}

// ServerKey derives a stable per-proxy key from the mapping's server+port so
// pool IDs stay stable across refreshes that reorder the list.
func ServerKey(m map[string]any) string {
	server, _ := m["server"].(string)
	port := fmt.Sprint(m["port"])
	if server == "" {
		if name, _ := m["name"].(string); name != "" {
			return name
		}
		return "unknown"
	}
	return server + ":" + port
}

// boxCtx is the shared sing-box construction context, built once. See the
// package comment: it mirrors box.New's manager construction so outbounds
// created from the registry find their services (DNS resolution for domain
// servers, network manager, connection manager) in the context.
var (
	boxCtxOnce sync.Once
	boxCtx     context.Context
	boxCtxErr  error

	// boxOutboundRegistry is the outbound registry installed in boxCtx. It is
	// assigned by buildBoxContext and read by the outbound factory.
	boxOutboundRegistry adapter.OutboundRegistry
)

func getBoxContext() (context.Context, error) {
	boxCtxOnce.Do(func() {
		boxCtxErr = buildBoxContext()
	})
	return boxCtx, boxCtxErr
}

// buildBoxContext constructs the minimal service context sing-box outbounds
// expect, following box.New's ordering: registries (via include.Context),
// pause manager, log factory, managers (outbound, DNS transport, DNS
// router, network, connection), then the default-outbound and local-DNS
// fallbacks.
func buildBoxContext() error {
	ctx := context.Background()
	outboundRegistry := include.OutboundRegistry()
	dnsTransportRegistry := include.DNSTransportRegistry()
	ctx = include.Context(ctx)
	ctx = service.ContextWithDefaultRegistry(ctx)
	ctx = pause.WithDefaultManager(ctx)
	if service.PtrFromContext[urltest.HistoryStorage](ctx) == nil {
		ctx = service.ContextWithPtr(ctx, urltest.NewHistoryStorage())
	}
	logFactory := log.NewNOPFactory()
	service.MustRegister[log.Factory](ctx, logFactory)

	endpointManager := boxEndpoint.NewManager(logFactory.NewLogger("endpoint"), include.EndpointRegistry())
	inboundManager := boxInbound.NewManager(logFactory.NewLogger("inbound"), include.InboundRegistry(), endpointManager)
	outboundManager := boxOutbound.NewManager(logFactory.NewLogger("outbound"), outboundRegistry, endpointManager, "")
	dnsTransportManager := dns.NewTransportManager(logFactory.NewLogger("dns/transport"), dnsTransportRegistry, outboundManager, "")
	service.MustRegister[adapter.EndpointManager](ctx, endpointManager)
	service.MustRegister[adapter.InboundManager](ctx, inboundManager)
	service.MustRegister[adapter.OutboundManager](ctx, outboundManager)
	service.MustRegister[adapter.DNSTransportManager](ctx, dnsTransportManager)

	dnsRouter, err := dns.NewRouter(ctx, logFactory, option.DNSOptions{})
	if err != nil {
		return fmt.Errorf("singbox: dns router: %w", err)
	}
	service.MustRegister[adapter.DNSRouter](ctx, dnsRouter)

	networkManager, err := route.NewNetworkManager(ctx, logFactory.NewLogger("network"), option.RouteOptions{}, option.DNSOptions{})
	if err != nil {
		return fmt.Errorf("singbox: network manager: %w", err)
	}
	service.MustRegister[adapter.NetworkManager](ctx, networkManager)
	service.MustRegister[adapter.ConnectionManager](ctx, route.NewConnectionManager(logFactory.NewLogger("connection")))

	// Default-outbound and local-DNS fallbacks, mirroring box.New: they are
	// consulted lazily (only when an outbound actually needs them), which is
	// what makes domain server addresses resolve through the system DNS.
	outboundManager.Initialize(func() (adapter.Outbound, error) {
		return outboundRegistry.CreateOutbound(
			ctx, nil, logFactory.NewLogger("outbound/direct"), "direct", "direct", option.DirectOutboundOptions{},
		)
	})
	dnsTransportManager.Initialize(func() (adapter.DNSTransport, error) {
		return dnsTransportRegistry.CreateDNSTransport(
			ctx, logFactory.NewLogger("dns/local"), "local", "local", &option.LocalDNSServerOptions{},
		)
	})

	// Export the registry the outbound factory dials through. include.Context
	// installed the same instance in the context; the local reference avoids a
	// service.FromContext lookup on every build.
	boxOutboundRegistry = outboundRegistry

	boxCtx = ctx
	return nil
}
