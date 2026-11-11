package adapter

import (
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestHeySocksProfile(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name": "test", "type": "heysocks-xhttp", "server": "127.0.0.1", "port": 1,
		"cipher": "aes-128-ctr", "password": "test-secret:03616263",
		"fake-net": map[string]any{"tcp": "010203"},
		"udp":      true, "udp-over-tcp": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	if proxy.Type() != C.HeySocks || proxy.Type().String() != "HeySocks" {
		t.Fatal("incorrect adapter type")
	}
	if !proxy.SupportUDP() || !proxy.SupportUOT() {
		t.Fatal("UDP-over-TCP capability missing")
	}
}

func TestHeySocksUnsupportedDatagrams(t *testing.T) {
	_, err := ParseProxy(map[string]any{
		"name": "test", "type": "heysocks-xhttp", "server": "127.0.0.1", "port": 1,
		"cipher": "aes-128-ctr", "password": "test-secret:03616263", "udp": true,
		"fake-net": map[string]any{"tcp": "010203"},
	})
	if err == nil || !strings.Contains(err.Error(), "udp-over-tcp") {
		t.Fatalf("expected an explicit UDP-over-TCP requirement, got %v", err)
	}
}
