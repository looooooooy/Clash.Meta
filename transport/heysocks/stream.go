package heysocks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
)

type Client struct {
	block    cipher.Block
	identity [md5.Size]byte
	prefix   []byte
	mu       sync.RWMutex
	token    []byte
}

func NewClient(method, password, tcpPrefix string) (*Client, error) {
	if method != "aes-128-ctr" {
		return nil, errors.New("heysocks: unsupported cipher")
	}
	secret, encoded, ok := strings.Cut(password, ":")
	if !ok || secret == "" {
		return nil, errors.New("heysocks: invalid credential format")
	}
	token, err := hex.DecodeString(encoded)
	if err != nil || len(token) == 0 || int(token[0]) != len(token)-1 {
		return nil, errors.New("heysocks: invalid authorization token")
	}
	prefix, err := hex.DecodeString(tcpPrefix)
	if err != nil || len(prefix) > 128 {
		return nil, errors.New("heysocks: invalid TCP preamble")
	}
	key := md5.Sum([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return &Client{
		block:    block,
		identity: md5.Sum([]byte(secret + "do not hack this protocol please")),
		prefix:   prefix,
		token:    token,
	}, nil
}

func (c *Client) StreamConn(raw net.Conn, destination []byte) (net.Conn, error) {
	if len(destination) == 0 {
		return nil, errors.New("heysocks: missing destination")
	}
	c.mu.RLock()
	token := append([]byte(nil), c.token...)
	c.mu.RUnlock()
	header := make([]byte, 128+md5.Size+len(token)+1+aes.BlockSize)
	copy(header, c.prefix)
	if _, err := io.ReadFull(rand.Reader, header[len(c.prefix):128]); err != nil {
		return nil, err
	}
	copy(header[128:], c.identity[:])
	copy(header[128+md5.Size:], token)
	ivOffset := 128 + md5.Size + len(token) + 1
	header[ivOffset-1] = aes.BlockSize
	iv := header[ivOffset:]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	writer := cipher.NewCTR(c.block, iv)
	encrypted := make([]byte, len(destination))
	writer.XORKeyStream(encrypted, destination)
	if _, err := writeAll(raw, append(header, encrypted...)); err != nil {
		return nil, err
	}
	return &Conn{Conn: raw, client: c, writer: writer}, nil
}

type Conn struct {
	net.Conn
	client   *Client
	reader   cipher.Stream
	writer   cipher.Stream
	readMu   sync.Mutex
	writeMu  sync.Mutex
	readOnce sync.Once
	readErr  error
}

func (c *Conn) readHeader() error {
	header := make([]byte, 128+md5.Size+1)
	if _, err := io.ReadFull(c.Conn, header); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(header[128:128+md5.Size], c.client.identity[:]) != 1 {
		return errors.New("heysocks: response identity mismatch")
	}
	token := make([]byte, int(header[len(header)-1])+1)
	token[0] = header[len(header)-1]
	if _, err := io.ReadFull(c.Conn, token[1:]); err != nil {
		return err
	}
	var size [1]byte
	if _, err := io.ReadFull(c.Conn, size[:]); err != nil {
		return err
	}
	if size[0] != aes.BlockSize {
		return errors.New("heysocks: invalid response IV size")
	}
	var iv [aes.BlockSize]byte
	if _, err := io.ReadFull(c.Conn, iv[:]); err != nil {
		return err
	}
	c.reader = cipher.NewCTR(c.client.block, iv[:])
	c.client.mu.Lock()
	c.client.token = token
	c.client.mu.Unlock()
	return nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.readOnce.Do(func() { c.readErr = c.readHeader() })
	if c.readErr != nil {
		return 0, c.readErr
	}
	n, err := c.Conn.Read(p)
	c.reader.XORKeyStream(p[:n], p[:n])
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	var total int
	buffer := make([]byte, minInt(len(p), 32*1024))
	for len(p) > 0 {
		chunk := minInt(len(p), len(buffer))
		c.writer.XORKeyStream(buffer[:chunk], p[:chunk])
		n, err := writeAll(c.Conn, buffer[:chunk])
		total += n
		if err != nil {
			_ = c.Conn.Close()
			return total, err
		}
		p = p[chunk:]
	}
	return total, nil
}

func writeAll(w io.Writer, p []byte) (int, error) {
	var total int
	for len(p) > 0 {
		n, err := w.Write(p)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
