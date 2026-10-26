//go:build !with_quic

package singbox

import "fmt"

// quicSupported: no QUIC outbounds exist without the with_quic build tag, so
// the provider skips hysteria/hysteria2/tuic subscription entries instead of
// registering protocols that cannot dial.
func quicSupported(string) bool { return false }

// convertQuic errors rather than panicking on the QUIC types. ProtocolOf
// rejects them in this build, so only a hand-built mapping could get here.
func convertQuic(sbType string, _ map[string]any) (any, error) {
	return nil, fmt.Errorf("type %q needs goose built with -tags with_quic", sbType)
}
