package outbound

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

func TestProbeConnectsReadyIPWhileAnotherDNSLookupStalls(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	dialer := &net.Dialer{}
	started := time.Now()
	delay, err := probeHeySocksEndpoints(
		ctx,
		[]string{"slow.example:443", listener.Addr().String()},
		nil,
		C.DualStack,
		dialer.DialContext,
		func(ctx context.Context, host string) ([]netip.Addr, error) {
			if host == "slow.example" {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return []netip.Addr{netip.MustParseAddr(host)}, nil
		},
	)
	if err != nil {
		t.Fatalf("probeHeySocksEndpoints() error = %v", err)
	}
	if delay == 0 || !time.Now().Before(deadline) {
		t.Fatalf("probe took %v and returned %d ms", time.Since(started), delay)
	}
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("probe did not connect to the ready IP")
	}
}

func TestProbeUsesFallbackAfterDNSBudgetExpires(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
			accepted <- struct{}{}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	dialer := &net.Dialer{}
	delay, err := probeHeySocksEndpoints(
		ctx,
		[]string{"slow.example:" + portOf(listener.Addr())},
		map[string]string{"slow.example": "127.0.0.1"},
		C.DualStack,
		dialer.DialContext,
		func(ctx context.Context, _ string) ([]netip.Addr, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)
	if err != nil {
		t.Fatalf("probeHeySocksEndpoints() error = %v", err)
	}
	if delay == 0 || !time.Now().Before(deadline) {
		t.Fatalf("probe did not connect before its deadline: delay=%d", delay)
	}
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("probe did not connect to the fallback IP")
	}
}

func portOf(address net.Addr) string {
	_, port, err := net.SplitHostPort(address.String())
	if err != nil {
		panic(err)
	}
	return port
}
