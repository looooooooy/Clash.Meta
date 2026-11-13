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
	targets, err := resolveHeySocksProbeEndpoints(ctx, endpoints, h.option.ProbeEndpointFallbackResolver)
	if err != nil {
		return 0, err
	}
	if h.prefer == C.IPv4Only || h.prefer == C.IPv6Only {
		filtered := targets[:0]
		for _, target := range targets {
			if (h.prefer == C.IPv4Only && target.ip.Is4()) || (h.prefer == C.IPv6Only && target.ip.Is6()) {
				filtered = append(filtered, target)
			}
		}
		targets = filtered
	}
	if len(targets) == 0 {
		return 0, resolver.ErrIPNotFound
	}

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	delays := make(chan uint16, len(targets))
	var firstErr error
	var firstErrOnce sync.Once
	var wait sync.WaitGroup
	for _, target := range targets {
		wait.Add(1)
		go func(target heySocksProbeTarget) {
			defer wait.Done()
			started := time.Now()
			conn, err := h.dialer.DialContext(
				probeCtx,
				"tcp",
				net.JoinHostPort(target.ip.String(), strconv.Itoa(int(target.port))),
			)
			if err != nil {
				firstErrOnce.Do(func() { firstErr = err })
				return
			}
			delay := uint16(time.Since(started) / time.Millisecond)
			_ = conn.Close()
			if delay == 0 {
				delay = 1
			}
			delays <- delay
			cancel()
		}(target)
	}
	wait.Wait()
	close(delays)

	var fastest uint16
	for delay := range delays {
		if fastest == 0 || delay < fastest {
			fastest = delay
		}
	}
	if fastest == 0 {
		return 0, firstErr
	}
	return fastest, nil
}

type heySocksProbeTarget struct {
	ip   netip.Addr
	port uint16
}

func resolveHeySocksProbeEndpoints(ctx context.Context, endpoints []string, fallback map[string]string) ([]heySocksProbeTarget, error) {
	type probeEndpoint struct {
		host string
		port uint16
	}
	parsed := make([]probeEndpoint, 0, len(endpoints))
	hosts := make(map[string]bool, len(endpoints))
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
		parsed = append(parsed, probeEndpoint{host: host, port: uint16(port)})
		hosts[host] = true
	}

	type resolution struct {
		ips []netip.Addr
		err error
	}
	resolved := make(map[string]resolution, len(hosts))
	var resolveWait sync.WaitGroup
	var resolveMu sync.Mutex
	for host := range hosts {
		resolveWait.Add(1)
		go func(host string) {
			defer resolveWait.Done()
			ips, err := resolveHeySocksEndpoint(ctx, host)
			if err != nil || len(ips) == 0 {
				fallbackIPs := fallback[host]
				if fallbackIPs == "" {
					fallbackIPs = fallback[strings.ToLower(host)]
				}
				ips = parseHeySocksFallbackIPs(fallbackIPs)
				if len(ips) > 0 {
					err = nil
				} else if err == nil {
					err = resolver.ErrIPNotFound
				}
			}
			resolveMu.Lock()
			resolved[host] = resolution{ips: ips, err: err}
			resolveMu.Unlock()
		}(host)
	}
	resolveWait.Wait()

	seen := map[heySocksProbeTarget]bool{}
	targets := make([]heySocksProbeTarget, 0, len(parsed))
	for _, endpoint := range parsed {
		result := resolved[endpoint.host]
		if len(result.ips) == 0 {
			if firstErr == nil {
				firstErr = result.err
			}
			continue
		}
		for _, ip := range result.ips {
			target := heySocksProbeTarget{ip: ip.Unmap(), port: endpoint.port}
			if !seen[target] {
				seen[target] = true
				targets = append(targets, target)
			}
		}
	}
	if len(targets) == 0 {
		if firstErr == nil {
			firstErr = resolver.ErrIPNotFound
		}
		return nil, firstErr
	}
	return targets, nil
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
