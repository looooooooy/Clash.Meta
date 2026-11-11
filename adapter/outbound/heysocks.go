package outbound

import (
	"context"
	"errors"
	"net"
	"strconv"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/heysocks"
	"github.com/metacubex/mihomo/transport/socks5"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type HeySocksOption struct {
	BasicOption
	Name              string            `proxy:"name"`
	Server            string            `proxy:"server"`
	Port              int               `proxy:"port"`
	Password          string            `proxy:"password"`
	Cipher            string            `proxy:"cipher"`
	FakeNet           map[string]string `proxy:"fake-net"`
	UDP               bool              `proxy:"udp,omitempty"`
	UDPOverTCP        bool              `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion int               `proxy:"udp-over-tcp-version,omitempty"`
}

type HeySocks struct {
	*Base
	option HeySocksOption
	client *heysocks.Client
}

func NewHeySocks(option HeySocksOption) (*HeySocks, error) {
	if option.Server == "" || option.Port < 1 || option.Port > 65535 {
		return nil, errors.New("heysocks: invalid server or port")
	}
	if option.UDP && !option.UDPOverTCP {
		return nil, errors.New("heysocks: UDP requires udp-over-tcp")
	}
	if option.UDPOverTCPVersion == 0 {
		option.UDPOverTCPVersion = uot.Version
	}
	if option.UDPOverTCPVersion != uot.Version && option.UDPOverTCPVersion != uot.LegacyVersion {
		return nil, errors.New("heysocks: unsupported UDP-over-TCP version")
	}
	client, err := heysocks.NewClient(option.Cipher, option.Password, option.FakeNet["tcp"])
	if err != nil {
		return nil, err
	}
	proxy := &HeySocks{
		Base: NewBase(BaseOption{
			Name: option.Name, Addr: net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			Type: C.HeySocks, ProviderName: option.ProviderName, UDP: option.UDP,
			TFO: option.TFO, MPTCP: option.MPTCP, Interface: option.Interface,
			RoutingMark: option.RoutingMark, Prefer: option.IPVersion,
		}),
		option: option, client: client,
	}
	proxy.dialer = option.NewDialer(proxy.DialOptions())
	return proxy, nil
}

func (h *HeySocks) StreamConnContext(ctx context.Context, conn net.Conn, metadata *C.Metadata) (_ net.Conn, err error) {
	if ctx.Done() != nil {
		done := N.SetupContextForConn(ctx, conn)
		defer done(&err)
	}
	destination := serializesSocksAddr(metadata)
	if metadata.NetWork == C.UDP {
		if !h.SupportUOT() {
			return nil, C.ErrNotSupport
		}
		destination = socks5.ParseAddr(uot.RequestDestination(uint8(h.option.UDPOverTCPVersion)).String())
	}
	return h.client.StreamConn(conn, destination)
}

func (h *HeySocks) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	raw, err := h.dialer.DialContext(ctx, "tcp", h.addr)
	if err != nil {
		return nil, err
	}
	defer func() { safeConnClose(raw, err) }()
	conn, err := h.StreamConnContext(ctx, raw, metadata)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, h), nil
}

func (h *HeySocks) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (_ C.PacketConn, err error) {
	if !h.SupportUDP() || !h.SupportUOT() {
		return nil, C.ErrNotSupport
	}
	if err = h.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	udpMetadata := *metadata
	udpMetadata.NetWork = C.UDP
	conn, err := h.DialContext(ctx, &udpMetadata)
	if err != nil {
		return nil, err
	}
	defer func() { safeConnClose(conn, err) }()
	request := uot.Request{Destination: M.SocksaddrFromNet(metadata.UDPAddr())}
	var packet net.PacketConn
	if h.option.UDPOverTCPVersion == uot.LegacyVersion {
		packet = uot.NewConn(conn, request)
	} else {
		packet = uot.NewLazyConn(conn, request)
	}
	return NewPacketConn(N.NewThreadSafePacketConn(packet), h), nil
}

func (h *HeySocks) SupportUOT() bool {
	return h.option.UDPOverTCP
}

func (h *HeySocks) ProxyInfo() C.ProxyInfo {
	info := h.Base.ProxyInfo()
	info.DialerProxy = h.option.DialerProxy
	return info
}
