package heysocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const fixturePassword = "interoperability-test:03616263"

func testClient(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient("aes-128-ctr", fixturePassword, "01020304")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type shortConn struct{ net.Conn }

func (c shortConn) Write(p []byte) (int, error) {
	return c.Conn.Write(p[:minInt(len(p), 7)])
}

func TestIndependentPeerAndPartialWrites(t *testing.T) {
	client := testClient(t)
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })
	_ = local.SetDeadline(time.Now().Add(5 * time.Second))
	_ = remote.SetDeadline(time.Now().Add(5 * time.Second))
	destination := []byte{1, 127, 0, 0, 1, 0, 80}
	payload := bytes.Repeat([]byte("large encrypted stream\n"), 5000)
	peerDone := make(chan error, 1)
	go func() {
		header := make([]byte, 128+16+4+1+16)
		if _, err := io.ReadFull(remote, header); err != nil {
			peerDone <- err
			return
		}
		key := md5.Sum([]byte("interoperability-test"))
		identity := md5.Sum([]byte("interoperability-testdo not hack this protocol please"))
		if !bytes.Equal(header[:4], []byte{1, 2, 3, 4}) || !bytes.Equal(header[128:144], identity[:]) || !bytes.Equal(header[144:148], []byte{3, 'a', 'b', 'c'}) || header[148] != 16 {
			peerDone <- errors.New("unexpected client preamble")
			return
		}
		block, _ := aes.NewCipher(key[:])
		incoming := make([]byte, len(destination)+len(payload))
		if _, err := io.ReadFull(remote, incoming); err != nil {
			peerDone <- err
			return
		}
		cipher.NewCTR(block, header[149:165]).XORKeyStream(incoming, incoming)
		if !bytes.Equal(incoming, append(append([]byte(nil), destination...), payload...)) {
			peerDone <- errors.New("incorrect encrypted address or payload")
			return
		}
		iv := bytes.Repeat([]byte{0x42}, 16)
		response := append(make([]byte, 128), identity[:]...)
		response = append(response, 2, 'o', 'k', 16)
		response = append(response, iv...)
		encrypted := make([]byte, len(payload))
		cipher.NewCTR(block, iv).XORKeyStream(encrypted, payload)
		_, err := writeAll(shortConn{remote}, append(response, encrypted...))
		peerDone <- err
	}()
	conn, err := client.StreamConn(shortConn{local}, destination)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write count=%d error=%v", n, err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("response plaintext differs")
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	client.mu.RLock()
	defer client.mu.RUnlock()
	if !bytes.Equal(client.token, []byte{2, 'o', 'k'}) {
		t.Fatal("server token refresh was not retained")
	}
}

func TestResponseRejectsMalformedHeaders(t *testing.T) {
	identity := md5.Sum([]byte("interoperability-testdo not hack this protocol please"))
	validPrefix := append(make([]byte, 128), identity[:]...)
	for name, response := range map[string][]byte{
		"truncated":       {0, 1},
		"wrong identity":  make([]byte, 145),
		"wrong IV length": append(append([]byte(nil), validPrefix...), 0, 15),
		"truncated token": append(append([]byte(nil), validPrefix...), 4, 1),
	} {
		t.Run(name, func(t *testing.T) {
			local, remote := net.Pipe()
			defer local.Close()
			_ = local.SetDeadline(time.Now().Add(time.Second))
			go func() { defer remote.Close(); _, _ = remote.Write(response) }()
			conn := &Conn{Conn: local, client: testClient(t)}
			var value [1]byte
			if _, err := conn.Read(value[:]); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func TestInvalidOptionsDoNotExposeCredentials(t *testing.T) {
	for _, tc := range []struct{ method, password, prefix string }{
		{"unsupported", fixturePassword, ""},
		{"aes-128-ctr", "sensitive-value", ""},
		{"aes-128-ctr", "sensitive-value:ffff", ""},
		{"aes-128-ctr", fixturePassword, "zz"},
		{"aes-128-ctr", fixturePassword, hex.EncodeToString(make([]byte, 129))},
	} {
		_, err := NewClient(tc.method, tc.password, tc.prefix)
		if err == nil {
			t.Fatal("invalid options accepted")
		}
		if strings.Contains(err.Error(), tc.password) {
			t.Fatal("credential exposed in error")
		}
	}
}

type stalledWriter struct{}

func (stalledWriter) Write([]byte) (int, error) { return 0, nil }

func TestWriteAllRejectsNoProgress(t *testing.T) {
	if _, err := writeAll(stalledWriter{}, []byte("data")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("unexpected error: %v", err)
	}
}
