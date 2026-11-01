package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

// proxyV2 builds a PROXY v2 header (TCP over IPv4) with the given command
// and raw TLV bytes.
func proxyV2(cmd byte, tlvs ...[]byte) []byte {
	var b bytes.Buffer
	b.Write(proxyV2Signature)
	b.WriteByte(0x20 | cmd)
	b.WriteByte(0x11) // AF_INET, STREAM
	body := []byte{10, 0, 0, 1, 10, 0, 0, 2, 0x30, 0x39, 0x1f, 0x90}
	for _, t := range tlvs {
		body = append(body, t...)
	}
	l := make([]byte, 2)
	binary.BigEndian.PutUint16(l, uint16(len(body)))
	b.Write(l)
	b.Write(body)
	return b.Bytes()
}

func tlv(typ byte, v string) []byte {
	out := []byte{typ, 0, 0}
	binary.BigEndian.PutUint16(out[1:3], uint16(len(v)))
	return append(out, v...)
}

func TestReadProxyV2(t *testing.T) {
	const peer = "spiffe://substrate-actor.local/worker-for-actor/ax-lab/sbx-1"
	cases := []struct {
		name    string
		in      []byte
		want    string
		wantErr bool
	}{
		{"identity tlv", proxyV2(1, tlv(0x04, "noop"), tlv(0xE0, peer)), peer, false},
		{"no identity tlv", proxyV2(1, tlv(0x04, "noop")), "", false},
		{"repeated identity", proxyV2(1, tlv(0xE0, peer), tlv(0xE0, "other")), "", true},
		{"local command", proxyV2(0), "", true},
		{"plain http", []byte("GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n"), "", true},
		{"truncated tlv", proxyV2(1, []byte{0xE0, 0, 9, 'a'}), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readProxyV2(bufio.NewReader(bytes.NewReader(tc.in)), 0xE0)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestReadProxyV2LeavesPayload(t *testing.T) {
	in := append(proxyV2(1, tlv(0xE0, "id")), []byte("GET / HTTP/1.1\r\n")...)
	r := bufio.NewReader(bytes.NewReader(in))
	got, err := readProxyV2(r, 0xE0)
	require.NoError(t, err)
	require.Equal(t, "id", got)
	rest, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "GET / HTTP/1.1\r\n", string(rest))
}

// serveAndProbe serves one request on conn and reports the relay peer the
// handler saw ("" and false when none).
func serveAndProbe(t *testing.T, conn, client net.Conn) (string, bool) {
	t.Helper()
	type seen struct {
		peer string
		ok   bool
	}
	got := make(chan seen, 1)
	go func() {
		// The pipe closes after the single request; that error is expected.
		_ = serveOneHTTPConn(conn, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := transform.RelayPeer(r.Context())
			got <- seen{p, ok}
			w.WriteHeader(http.StatusNoContent)
		}))
	}()
	_, err := client.Write([]byte("GET http://x/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	s := <-got
	return s.peer, s.ok
}

func TestRelayPeerReachesRequestContext(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	rc := &relayConn{Conn: server, r: bufio.NewReader(server), peer: "spiffe://example/actor"}
	peer, ok := serveAndProbe(t, rc, client)
	require.True(t, ok)
	require.Equal(t, "spiffe://example/actor", peer)
}

func TestPlainConnHasNoRelayPeer(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	_, ok := serveAndProbe(t, server, client)
	require.False(t, ok)
}

func TestRelayPeerOfUnwrapsPeekedConn(t *testing.T) {
	_, server := net.Pipe()
	rc := &relayConn{Conn: server, r: bufio.NewReader(server), peer: "p"}
	peer, ok := relayPeerOf(newPeekedConn(rc, bufio.NewReader(rc)))
	require.True(t, ok)
	require.Equal(t, "p", peer)
	_, ok = relayPeerOf(server)
	require.False(t, ok)
}
