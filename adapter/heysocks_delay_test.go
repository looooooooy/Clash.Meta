package adapter_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
)

func TestHeySocksConnectionLatencyProbeDoesNotChangeHealthState(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	proxyAdapter, err := outbound.NewHeySocks(outbound.HeySocksOption{
		Name:     "HeySocks",
		Server:   "127.0.0.1",
		Port:     port,
		Password: "secret:00",
		Cipher:   "aes-128-ctr",
		FakeNet:  map[string]string{"tcp": ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := adapter.NewProxy(proxyAdapter)
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	previousDelay := proxy.LastDelayForTestUrl("not-an-url")
	delay, supported, err := proxy.TestConnectionLatency(ctx)
	if err != nil {
		t.Fatalf("TestConnectionLatency() error = %v", err)
	}
	if !supported {
		t.Fatal("TestConnectionLatency() is not supported by HeySocks")
	}
	if delay == 0 || delay >= 1000 {
		t.Fatalf("TestConnectionLatency() delay = %d ms, want a positive endpoint connect time", delay)
	}
	if got := proxy.LastDelayForTestUrl("not-an-url"); got != previousDelay {
		t.Fatalf("probe changed URLTest delay from %d to %d", previousDelay, got)
	}
	if !proxy.AliveForTestUrl("not-an-url") {
		t.Fatal("connection latency probe changed the URLTest health state")
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("listener.Accept() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("URLTest() did not connect to the HeySocks endpoint")
	}
}

func TestHeySocksHealthCheckDoesNotUseCatalogProbeEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err
	}()

	proxyAdapter, err := outbound.NewHeySocks(outbound.HeySocksOption{
		Name:                          "HeySocks",
		Server:                        "203.0.113.1",
		Port:                          443,
		Password:                      "secret:00",
		Cipher:                        "aes-128-ctr",
		FakeNet:                       map[string]string{"tcp": ""},
		ProbeEndpoints:                []string{listener.Addr().String()},
		ProbeEndpointFallbackResolver: map[string]string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := adapter.NewProxy(proxyAdapter)
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := proxy.URLTest(ctx, "not-an-url", nil); err == nil {
		t.Fatal("URLTest() unexpectedly passed without a valid test URL or working transport")
	}
	if proxy.AliveForTestUrl("not-an-url") {
		t.Fatal("failed URLTest() marked the proxy healthy")
	}
	select {
	case err := <-accepted:
		t.Fatalf("health check connected to the catalog-only probe endpoint: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	if _, supported, err := proxy.TestConnectionLatency(ctx); err != nil || !supported {
		t.Fatalf("catalog latency probe supported=%t error=%v", supported, err)
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("probe listener.Accept() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("URLTest() did not connect to the catalog probe endpoint")
	}
}
