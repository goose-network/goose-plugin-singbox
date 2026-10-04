// Module github.com/goose-network/goose-plugin-singbox is the sing-box
// subscription provider plugin for the goose proxy-pool engine.
//
// It embeds github.com/sagernet/sing-box as a Go library. A provider fetches
// a subscription URL (Clash YAML or V2Ray-style links), parses it with
// mihomo's battle-tested converters into proxy mappings, converts each
// mapping into a sing-box outbound option, and emits one goose outbound per
// proxy. Each outbound dials by building the sing-box outbound via its
// registry and calling DialContext with a parsed Socksaddr destination.
//
// Only the always-compiled sing-box outbound types are exposed: socks,
// http, shadowsocks, vmess, vless, trojan, snell, ssh, anytls, shadowtls.
// QUIC-based protocols (hysteria, hysteria2, tuic) need sing-box's
// with_quic build tag and are skipped when present in a subscription.
module github.com/goose-network/goose-plugin-singbox

go 1.26.0

toolchain go1.26.8

require (
	github.com/goose-network/goose-plugin-api v0.0.0
	github.com/metacubex/mihomo v0.0.0
	github.com/sagernet/sing v0.9.6-0.20260922013359-4ca3bebe0b8e
	github.com/sagernet/sing-box v0.0.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/RyuaNerin/go-krypto v1.3.0 // indirect
	github.com/Yawning/aez v0.0.0-20211027044916-e49e68abd344 // indirect
	github.com/ajg/form v1.7.1 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20231016080023-1a75b4708caa // indirect
	github.com/anchore/go-lzo v0.1.0 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/anthropics/anthropic-sdk-go v1.26.0 // indirect
	github.com/axiomhq/hyperloglog v0.0.0-20240319100328-84253e514e02 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/caddyserver/certmagic v0.25.3-0.20260421143802-60d9d8b415d6 // indirect
	github.com/caddyserver/zerossl v0.1.5 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/coreos/go-oidc/v3 v3.17.0 // indirect
	github.com/creack/pty v1.1.24 // indirect
	github.com/cretz/bine v0.2.0 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/database64128/tfo-go/v2 v2.3.2 // indirect
	github.com/dblohm7/wingoes v0.0.0-20240119213807-a09d6be7affa // indirect
	github.com/dgryski/go-camellia v0.0.0-20191119043421-69a8a13fb23d // indirect
	github.com/dgryski/go-metro v0.0.0-20180109044635-280f6062b5bc // indirect
	github.com/ebitengine/purego v0.10.0 // indirect
	github.com/ericlagergren/aegis v0.0.0-20250325060835-cd0defd64358 // indirect
	github.com/ericlagergren/polyval v0.0.0-20220411101811-e25bc10ba391 // indirect
	github.com/ericlagergren/siv v0.0.0-20220507050439-0b757b3aa5f1 // indirect
	github.com/ericlagergren/subtle v0.0.0-20220507045147-890d697da010 // indirect
	github.com/florianl/go-nfqueue/v2 v2.1.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/gaissmai/bart v0.26.1 // indirect
	github.com/go-chi/chi/v5 v5.2.5 // indirect
	github.com/go-chi/render v1.0.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.3 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go4org/hashtriemap v0.0.0-20251130024219-545ba229f689 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/gofrs/uuid/v5 v5.5.1 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/certificate-transparency-go v1.3.2 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/nftables v0.2.1-0.20240414091927-5e242ec57806 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20260220084031-5adc3eb26f91 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/jsimonetti/rtnetlink v1.4.1 // indirect
	github.com/keybase/go-keychain v0.0.1 // indirect
	github.com/klauspost/compress v1.19.1 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/koron/go-ssdp v0.0.4 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/libdns/acmedns v0.5.0 // indirect
	github.com/libdns/alidns v1.0.6 // indirect
	github.com/libdns/cloudflare v0.2.2 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/libp2p/go-nat v1.0.1-0.20250821073202-01afc089f138 // indirect
	github.com/libp2p/go-netroute v0.2.1 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/metacubex/ascon v0.1.0 // indirect
	github.com/metacubex/blake3 v0.1.0 // indirect
	github.com/metacubex/chacha v0.1.5 // indirect
	github.com/metacubex/cpu v0.1.1 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/http v0.1.7 // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/metacubex/randv2 v0.2.0 // indirect
	github.com/metacubex/sing v0.5.8 // indirect
	github.com/metacubex/sing-shadowsocks v0.2.13 // indirect
	github.com/metacubex/tls v0.1.8 // indirect
	github.com/metacubex/utls v1.8.7 // indirect
	github.com/mholt/acmez/v3 v3.1.6 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/oasisprotocol/deoxysii v0.0.0-20220228165953-2091330c22b7 // indirect
	github.com/openai/openai-go/v3 v3.26.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.27 // indirect
	github.com/pion/dtls/v3 v3.1.5 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pires/go-proxyproto v0.8.1 // indirect
	github.com/pkg/sftp v1.13.10 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/sagernet/bbolt v0.0.0-20260915102804-500ee1e84832 // indirect
	github.com/sagernet/cors v1.2.1 // indirect
	github.com/sagernet/cronet-go v0.0.0-20260912104727-0d28acc44093 // indirect
	github.com/sagernet/cronet-go/all v0.0.0-20260912104727-0d28acc44093 // indirect
	github.com/sagernet/cronet-go/lib/android_386 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/android_amd64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/android_arm v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/android_arm64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/darwin_amd64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/darwin_arm64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/ios_amd64_simulator v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/ios_arm64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/ios_arm64_simulator v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_386 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_386_musl v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_amd64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_amd64_musl v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_arm v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_arm64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_arm64_musl v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_arm_musl v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_loong64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_loong64_musl v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_mips64le v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_mipsle v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_mipsle_musl v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_riscv64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/linux_riscv64_musl v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/tvos_amd64_simulator v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/tvos_arm64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/tvos_arm64_simulator v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/windows_amd64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/cronet-go/lib/windows_arm64 v0.0.0-20260912104006-c10c03c318db // indirect
	github.com/sagernet/fswatch v0.1.2 // indirect
	github.com/sagernet/gliderssh v0.3.4-0.20260531100337-2194faca5648 // indirect
	github.com/sagernet/gvisor v0.0.0-20260727.0-sing-box-mod.1 // indirect
	github.com/sagernet/netlink v0.0.0-20260814022025-64455d367bbf // indirect
	github.com/sagernet/nftables v0.3.0-mod.4 // indirect
	github.com/sagernet/quic-go v0.61.0-sing-box-mod.7 // indirect
	github.com/sagernet/sing-anytls v0.0.0-20260904135308-cec2d74334be // indirect
	github.com/sagernet/sing-cloudflared v0.1.3-0.20260706062323-d9787e794aa3 // indirect
	github.com/sagernet/sing-mux v0.3.9-0.20260919141002-baf887b90a62 // indirect
	github.com/sagernet/sing-openconnect v0.0.0-20260903200519-8b89c968949d // indirect
	github.com/sagernet/sing-openvpn v0.0.0-20260903200517-e060dda5b1f1 // indirect
	github.com/sagernet/sing-quic v0.7.1-0.20260904135313-497364e8ee3e // indirect
	github.com/sagernet/sing-shadowsocks v0.2.8 // indirect
	github.com/sagernet/sing-shadowsocks2 v0.2.1 // indirect
	github.com/sagernet/sing-shadowtls v0.2.1 // indirect
	github.com/sagernet/sing-snell v0.0.0-20260904135315-bc5a12ac736f // indirect
	github.com/sagernet/sing-tun v0.9.6-0.20260922105247-aff4131a9e9e // indirect
	github.com/sagernet/sing-usbip v0.0.0-20260817040617-28bd42667eca // indirect
	github.com/sagernet/sing-vmess v0.2.8 // indirect
	github.com/sagernet/smux v1.5.50-sing-box-mod.1 // indirect
	github.com/sagernet/tailscale v1.102.1-sing-box-1.14-mod.5.0.20260916060041-a8fbeb4b0838 // indirect
	github.com/sagernet/wireguard-go v0.0.8-0.20260917055437-bc6039037038 // indirect
	github.com/sagernet/ws v0.0.0-20231204124109-acfe8907c854 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/sina-ghaderi/poly1305 v0.0.0-20220724002748-c5926b03988b // indirect
	github.com/sina-ghaderi/rabaead v0.0.0-20220730151906-ab6e06b96e8c // indirect
	github.com/sina-ghaderi/rabbitio v0.0.0-20220730151941-9ce26f4f872e // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/smallstep/pkcs7 v0.1.1 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/hujson v0.0.0-20260302212456-ecc657c15afd // indirect
	github.com/tailscale/netlink v1.1.1-0.20240822203006-4d49adab4de7 // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20250124233751-d4cd19a26976 // indirect
	github.com/tidwall/gjson v1.18.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	gitlab.com/go-extension/aes-ccm v0.0.0-20230221065045-e58665ef23c7 // indirect
	gitlab.com/yawning/bsaes.git v0.0.0-20190805113838-0a714cd429ec // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/exp v0.0.0-20260410095643-746e56fc9e2f // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/windows v0.5.3 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.1 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
	zombiezen.com/go/capnproto2 v2.18.2+incompatible // indirect
)

// Local checkouts: the api module, mihomo (link parsing) and sing-box live
// as sibling repos under /home/ubuntu/Downloads/proxy. These replaces make
// the plugin build against the local sources rather than (nonexistent)
// published versions.
replace github.com/goose-network/goose-plugin-api => ../goose-plugin-api

replace github.com/metacubex/mihomo => ../mihomo

replace github.com/sagernet/sing-box => ../sing-box
