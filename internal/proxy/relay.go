package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"
)

// The relay listener accepts connections from a trusted gateway (for example
// an egress Envoy that already authenticated the workload with mTLS). Every
// connection must start with a PROXY protocol v2 header; the configured TLV
// carries the identity the gateway verified for the workload behind it. The
// connection is then served exactly like a tunnel-listener HTTP proxy
// connection, with that identity attached to every request's context.
//
// Trust comes from the network: only the gateway may reach this listener
// (enforce with a NetworkPolicy or equivalent). The plain tunnel listener
// never parses PROXY headers, so a workload cannot assert an identity there.

const relayHeaderTimeout = 5 * time.Second

var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// relayConn is a relay-listener connection with the identity its PROXY
// header carried. peer is empty when the gateway sent no identity TLV.
type relayConn struct {
	net.Conn
	r    *bufio.Reader
	peer string
}

func (c *relayConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// relayPeerOf finds the relay identity of a (possibly wrapped) connection.
func relayPeerOf(c net.Conn) (string, bool) {
	for c != nil {
		switch v := c.(type) {
		case *relayConn:
			return v.peer, true
		case *peekedConn:
			c = v.Conn
		case *tls.Conn:
			c = v.NetConn()
		default:
			return "", false
		}
	}
	return "", false
}

func (p *Proxy) listenRelay() error {
	ln, err := net.Listen("tcp", p.relayAddr)
	if err != nil {
		return fmt.Errorf("relay listen: %w", err)
	}
	p.relayListener = ln
	p.logger.Info("relay proxy starting", slog.String("addr", ln.Addr().String()), slog.Int("peer_tlv", int(p.relayTLV)))
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.tunnelDone:
				return nil
			default:
			}
			p.logger.Warn("relay accept error", slog.String("error", err.Error()))
			continue
		}
		go p.handleRelay(conn)
	}
}

func (p *Proxy) handleRelay(conn net.Conn) {
	br := bufio.NewReader(conn)
	if err := conn.SetReadDeadline(time.Now().Add(relayHeaderTimeout)); err != nil {
		conn.Close()
		return
	}
	peer, err := readProxyV2(br, p.relayTLV)
	if err != nil {
		p.logger.Warn("relay rejected connection", slog.String("remote", conn.RemoteAddr().String()), slog.String("error", err.Error()))
		conn.Close()
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		conn.Close()
		return
	}
	if err := p.serveTunnelProxyHTTP(&relayConn{Conn: conn, r: br, peer: peer}); err != nil {
		p.logger.Debug("relay http error", slog.String("error", err.Error()))
	}
}

// readProxyV2 consumes a PROXY protocol v2 header and returns the value of
// TLV type tlv (empty if absent). A missing or malformed header is an error:
// the relay listener never falls back to unauthenticated plain traffic.
func readProxyV2(r *bufio.Reader, tlv byte) (string, error) {
	head := make([]byte, 16)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", fmt.Errorf("reading PROXY v2 header: %w", err)
	}
	if !bytes.Equal(head[:12], proxyV2Signature) {
		return "", errors.New("missing PROXY v2 signature")
	}
	if head[12]>>4 != 2 {
		return "", fmt.Errorf("unsupported PROXY version %d", head[12]>>4)
	}
	cmd := head[12] & 0x0F
	n := int(binary.BigEndian.Uint16(head[14:16]))
	if n > 4096 {
		return "", fmt.Errorf("PROXY v2 header too long (%d bytes)", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", fmt.Errorf("reading PROXY v2 body: %w", err)
	}
	if cmd == 0x0 { // LOCAL: health check from the gateway itself; no workload behind it.
		return "", errors.New("PROXY v2 LOCAL command carries no workload")
	}
	if cmd != 0x1 {
		return "", fmt.Errorf("unsupported PROXY v2 command %d", cmd)
	}
	var addrLen int
	switch head[13] >> 4 { // address family
	case 0x1:
		addrLen = 12
	case 0x2:
		addrLen = 36
	case 0x3:
		addrLen = 216
	default:
		addrLen = 0
	}
	if addrLen > len(body) {
		return "", errors.New("PROXY v2 address block truncated")
	}
	tlvs := body[addrLen:]
	var peer string
	var found bool
	for len(tlvs) > 0 {
		if len(tlvs) < 3 {
			return "", errors.New("PROXY v2 TLV truncated")
		}
		typ := tlvs[0]
		l := int(binary.BigEndian.Uint16(tlvs[1:3]))
		if 3+l > len(tlvs) {
			return "", errors.New("PROXY v2 TLV value truncated")
		}
		if typ == tlv {
			if found {
				return "", errors.New("PROXY v2 identity TLV repeated")
			}
			peer, found = string(tlvs[3:3+l]), true
		}
		tlvs = tlvs[3+l:]
	}
	return peer, nil
}
