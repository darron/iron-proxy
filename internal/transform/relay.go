package transform

import "context"

type relayPeerKey struct{}

// WithRelayPeer marks ctx as belonging to a connection that arrived on the
// trusted relay listener, carrying the peer identity the relaying gateway
// asserted for it (possibly empty when the gateway sent none).
func WithRelayPeer(ctx context.Context, peer string) context.Context {
	return context.WithValue(ctx, relayPeerKey{}, peer)
}

// RelayPeer reports the gateway-asserted peer identity for a request that
// arrived on the trusted relay listener. ok is false for every other
// listener, where no such assertion is trusted.
func RelayPeer(ctx context.Context) (peer string, ok bool) {
	peer, ok = ctx.Value(relayPeerKey{}).(string)
	return peer, ok
}
