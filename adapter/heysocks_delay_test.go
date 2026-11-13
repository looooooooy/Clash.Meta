package adapter_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
)

func TestHeySocksURLTestMeasuresEndpointConnection(t *testing.T) {
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
	delay, err := proxy.URLTest(ctx, "not-an-url", nil)
	if err != nil {
		t.Fatalf("URLTest() error = %v", err)
	}
	if delay == 0 || delay >= 1000 {
		t.Fatalf("URLTest() delay = %d ms, want a positive endpoint connect time", delay)
	}
	if got := proxy.LastDelayForTestUrl("not-an-url"); got != delay {
		t.Fatalf("LastDelayForTestUrl() = %d, want %d", got, delay)
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

func TestHeySocksURLTestUsesCatalogProbeEndpoint(t *testing.T) {
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
	delay, err := proxy.URLTest(ctx, "not-an-url", nil)
	if err != nil {
		t.Fatalf("URLTest() error = %v", err)
	}
	if delay == 0 || delay >= 1000 {
		t.Fatalf("URLTest() delay = %d ms, want a positive probe endpoint connect time", delay)
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
