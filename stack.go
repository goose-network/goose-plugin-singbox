// stack.go routes the sing-box outbound's own server connections through
// the goose engine's network stack.
//
// The engine injects its layer-3/4 dialer into every outbound config map
// under goose-plugin-api's StackDialer key ("_dialer"). sing-box has no
// dial-func option on its protocol options, but every outbound options
// struct embeds option.DialerOptions, whose "detour" field names another
// sing-box outbound to dial through — and the detour dialer resolves that
// tag lazily against the shared outbound manager at first dial. So:
//
//   - buildBoxContext registers a "goose-engine-stack" outbound type on the
//     registry backing the shared manager; its DialContext/ListenPacket are
//     the engine's stack dialer;
//   - Outbound.ensure, when the engine injected a stack, creates that
//     bridge in the manager once and points the converted options'
//     DialerOptions.Detour at it.
//
// The proxy's connection to its server then traverses the engine's
// network stack in process — no socket sing-box owns — and a domain
// server address resolves inside the stack (a detour bypasses sing-box's
// own resolver: common/dialer.NewWithOptions leaves the destination for
// the detour dialer).
//
// QUIC protocols (hysteria, hysteria2, tuic — with_quic builds) keep
// their kernel dials: their clients want an unbound batch-capable UDP
// socket, which the engine stack's connected-stream contract does not
// provide.
package singbox

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	boxOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	pub "github.com/goose-network/goose-plugin-api"
)

// engineStackType is the sing-box outbound type and manager tag of the
// engine-stack bridge. One fixed tag serves the whole process, like the
// shared construction context: the engine injects the same stack dialer
// into every outbound config.
const engineStackType = "goose-engine-stack"

// engineStackDialerOptions is the (empty) options value the bridge is
// created with; the dialer itself lives in engineStackDialer so any
// outbound's config can publish it before the first dial.
type engineStackDialerOptions struct{}

// engineStackDialer holds the stack dialer the bridge dials through. The
// engine injects one stack per process (the router's), so one global slot
// is exact; the atomic pointer keeps the lazy publish race-free.
var engineStackDialer atomic.Pointer[pub.StackDialer]

// registerEngineStackOutbound registers the bridge outbound type on the
// registry backing the shared outbound manager. include.OutboundRegistry()
// builds a fresh registry per call, so this must run on the very instance
// buildBoxContext captured — which it does, as one of its first acts.
func registerEngineStackOutbound(registry *boxOutbound.Registry) {
	boxOutbound.Register[engineStackDialerOptions](registry, engineStackType, newEngineStackOutbound)
}

// engineStackOutbound is the sing-box outbound bridging dials to the
// engine's network stack: a dial is a stack dial to the same destination.
type engineStackOutbound struct {
	boxOutbound.Adapter
}

func newEngineStackOutbound(context.Context, adapter.Router, log.ContextLogger, string, engineStackDialerOptions) (adapter.Outbound, error) {
	return &engineStackOutbound{
		Adapter: boxOutbound.NewAdapter(engineStackType, engineStackType, []string{N.NetworkTCP, N.NetworkUDP}, nil),
	}, nil
}

// stackDialer returns the published engine stack, or an error explaining
// its absence (a config could publish a dialer only after a bridge dial
// started — in practice the factory publishes before any dial).
func stackDialer() (pub.StackDialer, error) {
	sd := engineStackDialer.Load()
	if sd == nil {
		return nil, fmt.Errorf("singbox: no engine stack dialer installed for %s", engineStackType)
	}
	return *sd, nil
}

func (o *engineStackOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	sd, err := stackDialer()
	if err != nil {
		return nil, err
	}
	return sd.Dial(ctx, stackNetwork(network), socksaddrTarget(destination))
}

// ListenPacket serves sing-box's packet flows (QUIC handshakes, UDP
// sub-features) with a connected UDP dial through the stack — the same
// semantics sing-box's detour gives a packet dialer: one fixed remote.
func (o *engineStackOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	sd, err := stackDialer()
	if err != nil {
		return nil, err
	}
	conn, err := sd.Dial(ctx, "udp", socksaddrTarget(destination))
	if err != nil {
		return nil, err
	}
	packetConn, ok := conn.(net.PacketConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("singbox: engine stack returned a non-packet UDP connection")
	}
	return packetConn, nil
}

// engineStackOnce guards creating the bridge in the shared manager; the
// detour dialer resolves the tag lazily at first dial, so ordering with
// the proxy outbounds' creation does not matter.
var (
	engineStackOnce sync.Once
	engineStackErr  error
)

// routeThroughEngineStack installs the engine stack for one converted
// outbound: publish the dialer, make sure the bridge outbound exists in
// the shared manager, and set the options' Detour to it. The Outbound
// factory calls it only when the engine injected a stack dialer
// (AsStackDialer); without one, outbounds dial through sing-box's own
// kernel dialer exactly as before.
func routeThroughEngineStack(stack pub.StackDialer, opts any) error {
	engineStackDialer.Store(&stack)
	engineStackOnce.Do(func() {
		ctx, err := getBoxContext()
		if err != nil {
			engineStackErr = err
			return
		}
		engineStackErr = boxOutboundManager.Create(
			ctx, boxRouter, log.NewNOPFactory().NewLogger("outbound/"+engineStackType),
			engineStackType, engineStackType, &engineStackDialerOptions{},
		)
	})
	if engineStackErr != nil {
		return fmt.Errorf("singbox: engine-stack bridge: %w", engineStackErr)
	}
	if !setDetour(opts, engineStackType) {
		return fmt.Errorf("singbox: %T options carry no DialerOptions to route through the engine stack", opts)
	}
	return nil
}

// setDetour points the options' embedded DialerOptions.Detour at the
// engine-stack bridge. Every sing-box outbound options type embeds
// option.DialerOptions — directly, or one level deep (snell's
// AbstractSnellOutboundOptions) — so one promoted-field lookup covers
// them all without a per-type switch. It reports false when opts has no
// such field (a type this plugin should not detour).
func setDetour(opts any, tag string) bool {
	v := reflect.ValueOf(opts)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return false
	}
	field := v.Elem().FieldByName("Detour")
	if !field.IsValid() || field.Kind() != reflect.String || !field.CanSet() {
		return false
	}
	field.SetString(tag)
	return true
}

// stackNetwork normalizes sing's network names ("tcp", "tcp4", ...) onto
// the engine stack's tcp/udp contract.
func stackNetwork(network string) string {
	if strings.Contains(network, "udp") {
		return "udp"
	}
	return "tcp"
}

// socksaddrTarget renders a sing-box destination as the host:port string
// the engine stack dials, trimming the trailing dot sing keeps on FQDNs
// (the stack's resolver — the system resolver or gvisor's — takes both,
// but the bare name is what net.JoinHostPort elsewhere produces).
func socksaddrTarget(destination M.Socksaddr) string {
	if destination.IsFqdn() {
		return net.JoinHostPort(strings.TrimSuffix(destination.Fqdn, "."), strconv.Itoa(int(destination.Port)))
	}
	return destination.String()
}
