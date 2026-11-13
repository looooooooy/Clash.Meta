package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/heysocks"
	"github.com/metacubex/mihomo/transport/socks5"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/uot"
)

type HeySocksOption struct {
	BasicOption
	Name                          string            `proxy:"name"`
	Server                        string            `proxy:"server"`
	Port                          int               `proxy:"port"`
	Password                      string            `proxy:"password"`
	Cipher                        string            `proxy:"cipher"`
	FakeNet                       map[string]string `proxy:"fake-net"`
	UDP                           bool              `proxy:"udp,omitempty"`
	UDPOverTCP                    bool              `proxy:"udp-over-tcp,omitempty"`
	UDPOverTCPVersion             int               `proxy:"udp-over-tcp-version,omitempty"`
	ProbeEndpoints                []string          `proxy:"probe-endpoints,omitempty"`
	ProbeEndpointFallbackResolver map[string]string `proxy:"probe-endpoint-fallback-resolver,omitempty"`
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

func (h *HeySocks) TestConnectionLatency(ctx context.Context) (uint16, error) {
	endpoints := h.option.ProbeEndpoints
	if len(endpoints) == 0 {
		endpoints = []string{h.addr}
	}
	return probeHeySocksEndpoints(ctx, endpoints, h.option.ProbeEndpointFallbackResolver,
		h.prefer, h.dialer.DialContext, resolveHeySocksEndpoint)
}

func probeHeySocksEndpoints(
	ctx context.Context,
	endpoints []string,
	fallback map[string]string,
	prefer C.DNSPrefer,
	dial func(context.Context, string, string) (net.Conn, error),
	resolve func(context.Context, string) ([]netip.Addr, error),
) (uint16, error) {
	portsByHost := make(map[string]map[uint16]bool, len(endpoints))
	var firstErr error
	for _, rawEndpoint := range endpoints {
		host, portText, err := net.SplitHostPort(strings.TrimSpace(rawEndpoint))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 || host == "" {
			if firstErr == nil {
				firstErr = net.InvalidAddrError(rawEndpoint)
			}
			continue
		}
		if portsByHost[host] == nil {
			portsByHost[host] = make(map[uint16]bool)
		}
		portsByHost[host][uint16(port)] = true
	}
	if len(portsByHost) == 0 {
		if firstErr == nil {
			firstErr = resolver.ErrIPNotFound
		}
		return 0, firstErr
	}

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	dnsTimeout := time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, ctx.Err()
		}
		if remaining/3 < dnsTimeout {
			dnsTimeout = remaining / 3
		}
	}
	dnsCtx, cancelDNS := context.WithTimeout(probeCtx, dnsTimeout)
	defer cancelDNS()

	delays := make(chan uint16, 1)
	var firstErrOnce sync.Once
	var wait sync.WaitGroup
	for host, ports := range portsByHost {
		wait.Add(1)
		go func(host string, ports map[uint16]bool) {
			defer wait.Done()
			ips, err := resolve(dnsCtx, host)
			if err != nil || len(ips) == 0 {
				fallbackIPs := fallback[host]
				if fallbackIPs == "" {
					fallbackIPs = fallback[strings.ToLower(host)]
				}
				ips = parseHeySocksFallbackIPs(fallbackIPs)
				if len(ips) == 0 {
					if err == nil {
						err = resolver.ErrIPNotFound
					}
					firstErrOnce.Do(func() { firstErr = err })
					return
				}
			}
			var targetWait sync.WaitGroup
			for _, rawIP := range ips {
				ip := rawIP.Unmap()
				if (prefer == C.IPv4Only && !ip.Is4()) || (prefer == C.IPv6Only && !ip.Is6()) {
					continue
				}
				for port := range ports {
					targetWait.Add(1)
					go func(ip netip.Addr, port uint16) {
						defer targetWait.Done()
						started := time.Now()
						conn, dialErr := dial(
							probeCtx,
							"tcp",
							net.JoinHostPort(ip.String(), strconv.Itoa(int(port))),
						)
						if dialErr != nil {
							firstErrOnce.Do(func() { firstErr = dialErr })
							return
						}
						delay := uint16(time.Since(started) / time.Millisecond)
						_ = conn.Close()
						if delay == 0 {
							delay = 1
						}
						select {
						case delays <- delay:
							cancel()
						case <-probeCtx.Done():
						}
					}(ip, port)
				}
			}
			targetWait.Wait()
		}(host, ports)
	}
	wait.Wait()
	select {
	case delay := <-delays:
		return delay, nil
	default:
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if firstErr == nil {
		firstErr = resolver.ErrIPNotFound
	}
	return 0, firstErr
}

func parseHeySocksFallbackIPs(value string) []netip.Addr {
	ips := make([]netip.Addr, 0)
	for _, candidate := range strings.Split(value, ",") {
		candidate = strings.TrimSpace(candidate)
		candidate = strings.TrimPrefix(strings.TrimSuffix(candidate, "]"), "[")
		ip, err := netip.ParseAddr(candidate)
		if err == nil {
			ips = append(ips, ip.Unmap())
		}
	}
	return ips
}

func resolveHeySocksEndpoint(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if systemResolver := resolver.SystemResolver; systemResolver != nil {
		return resolver.LookupIPWithResolver(ctx, host, systemResolver)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
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
