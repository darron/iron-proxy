package spiffejwtsvid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

type fakePods map[string]Pod // ip -> pod; missing = ErrNoPod

func (f fakePods) Resolve(_ context.Context, ip string) (Pod, error) {
	if ip == "10.0.0.99" {
		return Pod{}, ErrAmbiguousPod
	}
	p, ok := f[ip]
	if !ok {
		return Pod{}, ErrNoPod
	}
	return p, nil
}

type fakeFetcher struct {
	mu      sync.Mutex
	calls   int
	byUID   map[string][]SVID // pod uid -> svids
	lastAud string
	// podPending answers PermissionDenied for this many pod fetches first.
	podPending int
}

func (f *fakeFetcher) FetchJWTSVIDs(_ context.Context, aud string, sel []*types.Selector) ([]SVID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastAud = aud
	if len(sel) != 1 || sel[0].Type != "k8s" || !strings.HasPrefix(sel[0].Value, "pod-uid:") {
		return nil, errors.New("bad selector")
	}
	if f.podPending > 0 {
		f.podPending--
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}
	s, ok := f.byUID[strings.TrimPrefix(sel[0].Value, "pod-uid:")]
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no identity issued")
	}
	return s, nil
}

var t0 = time.Unix(1_800_000_000, 0)

func svid(id, tok string) SVID {
	return SVID{Token: tok, SPIFFEID: id, IssuedAt: t0, ExpiresAt: t0.Add(5 * time.Minute)}
}

func newTestTransform(t *testing.T, pods PodResolver, f SVIDFetcher) *Transform {
	t.Helper()
	tr, err := newFromConfig(config{
		TrustDomain: "sbx.interval.internal",
		IDPrefix:    "/sandbox/",
		Routes: []routeConfig{
			{Audience: "executor", Rules: []hostmatch.RuleConfig{{Host: "executor.mcp.local"}}},
			{Audience: "model-router", Rules: []hostmatch.RuleConfig{{Host: "router.local"}}},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), pods, f)
	require.NoError(t, err)
	tr.now = func() time.Time { return t0.Add(time.Minute) }
	return tr
}

func request(host, remote string, hdr http.Header) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://"+host+"/mcp/github", nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header[k] = v
	}
	return r
}

func run(t *testing.T, tr *Transform, mode transform.Mode, r *http.Request) (transform.TransformAction, map[string]any) {
	t.Helper()
	tctx := &transform.TransformContext{Mode: mode}
	res, err := tr.TransformRequest(context.Background(), tctx, r)
	require.NoError(t, err)
	return res.Action, tctx.DrainAnnotations()
}

func setup() (fakePods, *fakeFetcher) {
	pods := fakePods{
		"10.0.0.1": {Namespace: "opensandbox-lab", Name: "sb-a", UID: "uid-a"},
		"10.0.0.2": {Namespace: "opensandbox-lab", Name: "sb-b", UID: "uid-b"},
		"10.0.0.3": {Namespace: "opensandbox-lab", Name: "sb-c", UID: "uid-c"}, // no entry
	}
	f := &fakeFetcher{byUID: map[string][]SVID{
		"uid-a": {svid("spiffe://sbx.interval.internal/sandbox/kata/a", "tok-a")},
		"uid-b": {svid("spiffe://sbx.interval.internal/sandbox/kata/b", "tok-b")},
	}}
	return pods, f
}

func TestInjectsPerSandboxIdentity(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)

	ra := request("executor.mcp.local", "10.0.0.1:41000", nil)
	act, ann := run(t, tr, transform.ModeMITM, ra)
	require.Equal(t, transform.ActionContinue, act)
	require.Equal(t, "Bearer tok-a", ra.Header.Get(defaultHeader))
	require.Equal(t, "spiffe://sbx.interval.internal/sandbox/kata/a", ann["spiffe_id"])
	require.Equal(t, "uid-a", ann["pod_uid"])
	for _, v := range ann {
		if s, ok := v.(string); ok {
			require.NotContains(t, s, "tok-", "token leaked into audit annotations")
		}
	}
	require.Equal(t, "executor", f.lastAud)

	rb := request("executor.mcp.local", "10.0.0.2:41000", nil)
	act, _ = run(t, tr, transform.ModeMITM, rb)
	require.Equal(t, transform.ActionContinue, act)
	require.Equal(t, "Bearer tok-b", rb.Header.Get(defaultHeader))
}

func TestForgedHeaderIsStrippedEverywhere(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	forged := http.Header{defaultHeader: {"Bearer tok-b"}}

	// Matching host: replaced with A's own identity.
	r := request("executor.mcp.local", "10.0.0.1:1", forged)
	run(t, tr, transform.ModeMITM, r)
	require.Equal(t, []string{"Bearer tok-a"}, r.Header.Values(defaultHeader))

	// Non-matching host: removed, nothing injected.
	r = request("example.com", "10.0.0.1:1", forged)
	act, ann := run(t, tr, transform.ModeMITM, r)
	require.Equal(t, transform.ActionContinue, act)
	require.Empty(t, r.Header.Get(defaultHeader))
	require.NotNil(t, ann["stripped"])

	// Rejected request: the forged value must not survive either.
	r = request("executor.mcp.local", "10.0.0.50:1", forged)
	act, _ = run(t, tr, transform.ModeMITM, r)
	require.Equal(t, transform.ActionReject, act)
	require.Empty(t, r.Header.Get(defaultHeader))
}

func TestFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		mode   transform.Mode
		reason string
	}{
		{"unknown ip", "10.0.0.50:1", transform.ModeMITM, "no_pod"},
		{"ambiguous ip", "10.0.0.99:1", transform.ModeMITM, "ambiguous_pod"},
		{"no entry", "10.0.0.3:1", transform.ModeMITM, "svid_unavailable"},
		{"sni only", "10.0.0.1:1", transform.ModeSNIOnly, "mitm_required"},
		{"bad remoteaddr", "garbage", transform.ModeMITM, "bad_remote_addr"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pods, f := setup()
			tr := newTestTransform(t, pods, f)
			r := request("executor.mcp.local", tc.remote, nil)
			act, ann := run(t, tr, tc.mode, r)
			require.Equal(t, transform.ActionReject, act)
			require.Equal(t, tc.reason, ann["rejected"])
			require.Empty(t, r.Header.Get(defaultHeader))
		})
	}
}

func TestRejectsWrongTrustDomainOrMultipleSVIDs(t *testing.T) {
	pods, f := setup()
	f.byUID["uid-a"] = []SVID{svid("spiffe://evil.example/sandbox/kata/a", "tok")}
	f.byUID["uid-b"] = []SVID{svid("spiffe://sbx.interval.internal/sandbox/kata/b", "t1"), svid("spiffe://sbx.interval.internal/sandbox/kata/b2", "t2")}
	f.byUID["uid-c"] = []SVID{svid("spiffe://sbx.interval.internal/iron-proxy", "tok")}
	tr := newTestTransform(t, pods, f)
	for _, ip := range []string{"10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1"} {
		act, ann := run(t, tr, transform.ModeMITM, request("executor.mcp.local", ip, nil))
		require.Equal(t, transform.ActionReject, act, ip)
		require.Equal(t, "svid_unavailable", ann["rejected"], ip)
	}
}

func TestCacheRefreshAndRevocation(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	clock := t0.Add(time.Minute)
	tr.now = func() time.Time { return clock }

	run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.1:1", nil))
	run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.1:1", nil))
	require.Equal(t, 1, f.calls, "SVID should be cached before half-life")

	// Entry deleted on the SPIRE side: past half-life the next fetch fails and
	// the request is refused (no stale token is reused).
	delete(f.byUID, "uid-a")
	clock = t0.Add(3 * time.Minute)
	act, ann := run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.1:1", nil))
	require.Equal(t, transform.ActionReject, act)
	require.Equal(t, "svid_unavailable", ann["rejected"])

	// Pod deleted: the resolver no longer maps the IP, so the request is
	// refused immediately even though B's token is cached.
	run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.2:1", nil))
	delete(pods, "10.0.0.2")
	act, ann = run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.2:1", nil))
	require.Equal(t, transform.ActionReject, act)
	require.Equal(t, "no_pod", ann["rejected"])
}

func TestConnectPassesWithoutIdentity(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	r := httptest.NewRequest(http.MethodConnect, "http://executor.mcp.local:80", nil)
	r.Host = "executor.mcp.local:80"
	r.RemoteAddr = "10.0.0.50:1" // unknown source: still not refused at CONNECT
	r.Header.Set(defaultHeader, "Bearer forged")
	act, _ := run(t, tr, transform.ModeSNIOnly, r)
	require.Equal(t, transform.ActionContinue, act)
	require.Empty(t, r.Header.Get(defaultHeader))
	require.Equal(t, 0, f.calls)
}

func TestConfigValidation(t *testing.T) {
	base := config{TrustDomain: "sbx.interval.internal", IDPrefix: "/sandbox/", Routes: []routeConfig{{Audience: "a", Rules: []hostmatch.RuleConfig{{Host: "x"}}}}}
	cases := []struct {
		name string
		mut  func(c *config)
	}{
		{"no audience", func(c *config) { c.Routes = []routeConfig{{Rules: []hostmatch.RuleConfig{{Host: "x"}}}} }},
		{"route without rules", func(c *config) { c.Routes = []routeConfig{{Audience: "a"}} }},
		{"trust domain with scheme", func(c *config) { c.TrustDomain = "spiffe://sbx" }},
		{"root prefix", func(c *config) { c.IDPrefix = "/" }},
		{"relative prefix", func(c *config) { c.IDPrefix = "sandbox" }},
		{"no routes", func(c *config) { c.Routes = nil }},
		{"forbidden header", func(c *config) { c.Header = "Proxy-Authorization" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pods, f := setup()
			c := base
			tc.mut(&c)
			_, err := newFromConfig(c, slog.Default(), pods, f)
			require.Error(t, err)
		})
	}
	pods, f := setup()
	_, err := newFromConfig(base, slog.Default(), pods, f)
	require.NoError(t, err)
}

func kubePod(ns, name, uid, ip string, mods ...func(m map[string]any)) map[string]any {
	m := map[string]any{
		"metadata": map[string]any{"name": name, "namespace": ns, "uid": uid},
		"spec":     map[string]any{},
		"status":   map[string]any{"phase": "Running", "podIP": ip},
	}
	for _, mod := range mods {
		mod(m)
	}
	return m
}

// fakeAPIServer serves pod lists per namespace from items and records the
// last query and Authorization header.
type fakeAPIServer struct {
	mu        sync.Mutex
	items     map[string][]map[string]any // namespace -> pods
	gotQuery  string
	gotAuth   string
	gotPaths  []string
	srv       *httptest.Server
	tokenFile string
}

func newFakeAPIServer(t *testing.T) *fakeAPIServer {
	t.Helper()
	f := &fakeAPIServer{items: map[string][]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.gotQuery, f.gotAuth = r.URL.RawQuery, r.Header.Get("Authorization")
		f.gotPaths = append(f.gotPaths, r.URL.Path)
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/namespaces/"), "/")
		if len(parts) != 2 || parts[1] != "pods" {
			http.NotFound(w, r)
			return
		}
		// Encoding a map of plain values cannot fail.
		_ = json.NewEncoder(w).Encode(map[string]any{"items": f.items[parts[0]]})
	}))
	t.Cleanup(f.srv.Close)
	f.tokenFile = t.TempDir() + "/token"
	require.NoError(t, os.WriteFile(f.tokenFile, []byte("sa-token\n"), 0o600))
	return f
}

func (f *fakeAPIServer) set(ns string, pods ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[ns] = pods
}

func TestKubePodResolver(t *testing.T) {
	api := newFakeAPIServer(t)
	k := newKubePodResolverWithClient(kubeConfig{APIServer: api.srv.URL, TokenPath: api.tokenFile, Namespaces: []string{"opensandbox-lab"}, LabelSelector: "sbx-run", CacheTTL: time.Second}, api.srv.Client())
	clock := t0
	k.now = func() time.Time { return clock }

	api.set("opensandbox-lab", kubePod("opensandbox-lab", "sb-a", "uid-a", "10.0.0.1"))
	p, err := k.Resolve(context.Background(), "10.0.0.1")
	require.NoError(t, err)
	require.Equal(t, "uid-a", p.UID)
	require.Equal(t, "Bearer sa-token", api.gotAuth)
	require.Contains(t, api.gotQuery, "fieldSelector=status.podIP%3D10.0.0.1%2Cstatus.phase%3DRunning")
	require.Contains(t, api.gotQuery, "labelSelector=sbx-run")

	// Cached within TTL even if the pod disappears; refreshed after.
	api.set("opensandbox-lab")
	p, err = k.Resolve(context.Background(), "10.0.0.1")
	require.NoError(t, err)
	require.Equal(t, "uid-a", p.UID)
	clock = clock.Add(2 * time.Second)
	_, err = k.Resolve(context.Background(), "10.0.0.1")
	require.ErrorIs(t, err, ErrNoPod)

	// Local re-checks: terminating, hostNetwork, wrong IP, not Running are ignored.
	clock = clock.Add(2 * time.Second)
	api.set("opensandbox-lab",
		kubePod("opensandbox-lab", "del", "u1", "10.0.0.5", func(m map[string]any) {
			m["metadata"].(map[string]any)["deletionTimestamp"] = "2026-11-01T00:00:00Z"
		}),
		kubePod("opensandbox-lab", "host", "u2", "10.0.0.5", func(m map[string]any) { m["spec"] = map[string]any{"hostNetwork": true} }),
		kubePod("opensandbox-lab", "other", "u3", "10.0.0.6"),
		kubePod("opensandbox-lab", "pending", "u4", "10.0.0.5", func(m map[string]any) { m["status"].(map[string]any)["phase"] = "Pending" }),
	)
	_, err = k.Resolve(context.Background(), "10.0.0.5")
	require.ErrorIs(t, err, ErrNoPod)

	clock = clock.Add(2 * time.Second)
	api.set("opensandbox-lab", kubePod("opensandbox-lab", "x", "u5", "10.0.0.7"), kubePod("opensandbox-lab", "y", "u6", "10.0.0.7"))
	_, err = k.Resolve(context.Background(), "10.0.0.7")
	require.ErrorIs(t, err, ErrAmbiguousPod)
}

func TestKubePodResolverAcrossNamespaces(t *testing.T) {
	api := newFakeAPIServer(t)
	k := newKubePodResolverWithClient(kubeConfig{APIServer: api.srv.URL, TokenPath: api.tokenFile, Namespaces: []string{"opensandbox-lab", "opensandbox-kata-build"}, LabelSelector: "sbx-run", CacheTTL: time.Second}, api.srv.Client())
	clock := t0
	k.now = func() time.Time { return clock }

	// A pod in the second namespace resolves, and both namespaces are queried.
	api.set("opensandbox-kata-build", kubePod("opensandbox-kata-build", "build", "uid-b", "10.0.1.1"))
	p, err := k.Resolve(context.Background(), "10.0.1.1")
	require.NoError(t, err)
	require.Equal(t, Pod{Namespace: "opensandbox-kata-build", Name: "build", UID: "uid-b"}, p)
	require.Equal(t, []string{"/api/v1/namespaces/opensandbox-lab/pods", "/api/v1/namespaces/opensandbox-kata-build/pods"}, api.gotPaths)

	// The same IP claimed in two namespaces is ambiguous, never first-wins.
	clock = clock.Add(2 * time.Second)
	api.set("opensandbox-lab", kubePod("opensandbox-lab", "lab", "uid-a", "10.0.1.1"))
	_, err = k.Resolve(context.Background(), "10.0.1.1")
	require.ErrorIs(t, err, ErrAmbiguousPod)
}

func TestKubePodResolverConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  kubeConfig
	}{
		{"no namespaces", kubeConfig{LabelSelector: "sbx-run"}},
		{"empty namespace", kubeConfig{Namespaces: []string{""}, LabelSelector: "sbx-run"}},
		{"no label selector", kubeConfig{Namespaces: []string{"opensandbox-lab"}}},
		{"cache ttl too long", kubeConfig{Namespaces: []string{"opensandbox-lab"}, LabelSelector: "sbx-run", CacheTTL: time.Minute}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newKubePodResolver(tc.cfg)
			require.Error(t, err)
		})
	}
}

func TestObserveModeNeverBlocks(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		reason string
	}{
		{"unknown ip", "10.0.0.50:1", "no_pod"},
		{"ambiguous ip", "10.0.0.99:1", "ambiguous_pod"},
		{"no entry", "10.0.0.3:1", "svid_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pods, f := setup()
			tr := newTestTransform(t, pods, f)
			tr.observe = true
			r := request("executor.mcp.local", tc.remote, http.Header{defaultHeader: {"Bearer forged"}})
			act, ann := run(t, tr, transform.ModeMITM, r)
			require.Equal(t, transform.ActionContinue, act)
			require.Equal(t, tc.reason, ann["unidentified"])
			require.Nil(t, ann["rejected"])
			require.Empty(t, r.Header.Get(defaultHeader), "forged header must still be stripped")
		})
	}

	// Identifiable sources still get their identity in observe mode.
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	tr.observe = true
	r := request("executor.mcp.local", "10.0.0.1:1", nil)
	act, _ := run(t, tr, transform.ModeMITM, r)
	require.Equal(t, transform.ActionContinue, act)
	require.Equal(t, "Bearer tok-a", r.Header.Get(defaultHeader))
}

func TestModeConfig(t *testing.T) {
	pods, f := setup()
	base := config{TrustDomain: "sbx.interval.internal", IDPrefix: "/sandbox/", Routes: []routeConfig{{Audience: "a", Rules: []hostmatch.RuleConfig{{Host: "x"}}}}}
	for _, mode := range []string{"", "enforce", "observe"} {
		c := base
		c.Mode = mode
		tr, err := newFromConfig(c, slog.Default(), pods, f)
		require.NoError(t, err, mode)
		require.Equal(t, mode == "observe", tr.observe, mode)
	}
	c := base
	c.Mode = "permissive"
	_, err := newFromConfig(c, slog.Default(), pods, f)
	require.Error(t, err)
}

func TestAudiencePerRoute(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)

	_, ann := run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.1:1", nil))
	require.Equal(t, "executor", f.lastAud)
	require.Equal(t, "executor", ann["audience"])

	_, ann = run(t, tr, transform.ModeMITM, request("router.local", "10.0.0.1:1", nil))
	require.Equal(t, "model-router", f.lastAud)
	require.Equal(t, "model-router", ann["audience"])
	require.Equal(t, 2, f.calls, "each audience needs its own token, never a shared cache entry")

	// Unmatched hosts get no identity and no fetch.
	r := request("example.com", "10.0.0.1:1", nil)
	act, _ := run(t, tr, transform.ModeMITM, r)
	require.Equal(t, transform.ActionContinue, act)
	require.Empty(t, r.Header.Get(defaultHeader))
	require.Equal(t, 2, f.calls)
}

func TestCachePrunesExpiredEntries(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	clock := t0.Add(time.Minute)
	tr.now = func() time.Time { return clock }

	run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.2:1", nil))
	require.Len(t, tr.cache, 1)

	// B's token expires; storing A's token prunes it.
	clock = t0.Add(10 * time.Minute)
	f.byUID["uid-a"] = []SVID{{Token: "tok-a2", SPIFFEID: "spiffe://sbx.interval.internal/sandbox/kata/a", IssuedAt: clock, ExpiresAt: clock.Add(5 * time.Minute)}}
	run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.1:1", nil))
	require.Len(t, tr.cache, 1)
	_, ok := tr.cache[cacheKey{"pod:uid-a", "executor"}]
	require.True(t, ok)
}

type relayFetcher struct {
	fakeFetcher
	bySel map[string][]SVID // "type:value" -> svids
	// pending answers PermissionDenied for this many sbx fetches first (an
	// entry still propagating to the agent).
	pending int
	// otherErr, when set, is returned for sbx fetches instead.
	otherErr error
	// stall blocks sbx fetches until their context ends.
	stall bool
}

func (f *relayFetcher) FetchJWTSVIDs(ctx context.Context, aud string, sel []*types.Selector) ([]SVID, error) {
	if len(sel) == 1 && sel[0].Type == "sbx" {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		f.lastAud = aud
		if f.stall {
			f.mu.Unlock()
			<-ctx.Done()
			f.mu.Lock()
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		if f.otherErr != nil {
			return nil, f.otherErr
		}
		if f.pending > 0 {
			f.pending--
			return nil, status.Error(codes.PermissionDenied, "no identity issued")
		}
		s, ok := f.bySel[sel[0].Type+":"+sel[0].Value]
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "no identity issued")
		}
		return s, nil
	}
	return f.fakeFetcher.FetchJWTSVIDs(ctx, aud, sel)
}

const axPeer = "spiffe://substrate-actor.local/worker-for-actor/ax-lab/sbx-abc123"

func newRelayTransform(t *testing.T) (*Transform, *relayFetcher) {
	t.Helper()
	pods, base := setup()
	f := &relayFetcher{fakeFetcher: fakeFetcher{byUID: base.byUID}, bySel: map[string][]SVID{
		"sbx:ax-actor:sbx-abc123": {svid("spiffe://sbx.interval.internal/sandbox/ax/sbx-abc123/i/x", "tok-ax")},
	}}
	tr, err := newFromConfig(config{
		TrustDomain: "sbx.interval.internal",
		IDPrefix:    "/sandbox/",
		Routes:      []routeConfig{{Audience: "model-router", Rules: []hostmatch.RuleConfig{{Host: "router.local"}}}},
		Relay: &relayConfig{
			IDPattern:      `^spiffe://substrate-actor\.local/worker-for-actor/ax-lab/([^/]+)$`,
			SelectorType:   "sbx",
			SelectorPrefix: "ax-actor:",
			Source:         relaySourceConfig{Namespaces: []string{"ate-system"}, LabelSelector: "app=atenet-egress"},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), pods, f)
	require.NoError(t, err)
	tr.now = func() time.Time { return t0.Add(time.Minute) }
	tr.relay.source = fakePods{gatewayIP: {Namespace: "ate-system", Name: "atenet-egress-x", UID: "gw"}}
	return tr, f
}

const gatewayIP = "10.0.0.200"

func runCtx(t *testing.T, tr *Transform, ctx context.Context, r *http.Request) (transform.TransformAction, map[string]any) {
	t.Helper()
	tctx := &transform.TransformContext{Mode: transform.ModeMITM}
	res, err := tr.TransformRequest(ctx, tctx, r)
	require.NoError(t, err)
	return res.Action, tctx.DrainAnnotations()
}

func TestRelayedPeerGetsItsOwnIdentity(t *testing.T) {
	tr, f := newRelayTransform(t)
	// The relay path identifies the asserted peer, never the gateway's own
	// source IP.
	r := request("router.local", gatewayIP+":1", http.Header{defaultHeader: {"Bearer forged"}})
	act, ann := runCtx(t, tr, transform.WithRelayPeer(context.Background(), axPeer), r)
	require.Equal(t, transform.ActionContinue, act)
	require.Equal(t, []string{"Bearer tok-ax"}, r.Header.Values(defaultHeader))
	require.Equal(t, "spiffe://sbx.interval.internal/sandbox/ax/sbx-abc123/i/x", ann["spiffe_id"])
	require.Equal(t, axPeer, ann["relay_peer"])
	require.Nil(t, ann["pod_uid"])
	require.Equal(t, "model-router", f.lastAud)
}

func TestRelayedPeerFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		peer   string
		reason string
	}{
		{"no identity tlv", "", "relay_peer_mismatch"},
		{"other atespace", "spiffe://substrate-actor.local/worker-for-actor/other/sbx-abc123", "relay_peer_mismatch"},
		{"suffix smuggling", axPeer + "/extra", "relay_peer_mismatch"},
		{"unknown actor", "spiffe://substrate-actor.local/worker-for-actor/ax-lab/sbx-nope", "svid_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, _ := newRelayTransform(t)
			r := request("router.local", gatewayIP+":1", nil)
			act, ann := runCtx(t, tr, transform.WithRelayPeer(context.Background(), tc.peer), r)
			require.Equal(t, transform.ActionReject, act)
			require.Equal(t, tc.reason, ann["rejected"])
			require.Empty(t, r.Header.Get(defaultHeader))
		})
	}
}

func TestAdditionalRelayIdentityIsRouteScoped(t *testing.T) {
	const microPattern = `^spiffe://test-actor\.local/worker/(isolated(?:-docker)?/[^/?#]+)$`
	const model = "model.example"
	const executor = "executor.example"
	const files = "files.example"
	const identityBase = "spiffe://test-actor.local/worker/"
	for _, tc := range []struct {
		name, peer, host, token, audience string
	}{
		{"isolated model", identityBase + "isolated/same-name", model, "micro", "model-router"},
		{"Docker model", identityBase + "isolated-docker/same-name", model, "docker", "model-router"},
		{"legacy model", identityBase + "legacy/sample", model, "ax", "model-router"},
		{"legacy Executor", identityBase + "legacy/sample", executor, "ax", "executor"},
		{"isolated Executor", identityBase + "isolated/same-name", executor, "", ""},
		{"isolated files", identityBase + "isolated/same-name", files, "", ""},
		{"Docker Executor", identityBase + "isolated-docker/same-name", executor, "", ""},
		{"Docker files", identityBase + "isolated-docker/same-name", files, "", ""},
		{"other namespace", identityBase + "other/same-name", model, "", ""},
		{"invalid peer path", identityBase + "isolated/same-name/extra", model, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pods, _ := setup()
			f := &relayFetcher{bySel: map[string][]SVID{
				"sbx:worker:sample":                    {svid("spiffe://workload.example/sandbox/ax/a", "ax")},
				"sbx:worker:isolated/same-name":        {svid("spiffe://workload.example/sandbox/isolated/a", "micro")},
				"sbx:worker:isolated-docker/same-name": {svid("spiffe://workload.example/sandbox/isolated-docker/a", "docker")},
			}}
			tr, err := newFromConfig(config{
				TrustDomain: "workload.example", IDPrefix: "/sandbox/",
				Routes: []routeConfig{
					{Audience: "executor", Rules: []hostmatch.RuleConfig{{Host: executor}}},
					{Audience: "model-router", Rules: []hostmatch.RuleConfig{{Host: model}}, RelayIDPattern: microPattern},
					{Audience: "sbx-files", Rules: []hostmatch.RuleConfig{{Host: files}}},
				},
				Relay: &relayConfig{
					IDPattern:    `^spiffe://test-actor\.local/worker/legacy/([^/]+)$`,
					SelectorType: "sbx", SelectorPrefix: "worker:",
					Source: relaySourceConfig{Namespaces: []string{"gateway"}, LabelSelector: "app=relay"},
				},
			}, slog.Default(), pods, f)
			require.NoError(t, err)
			tr.now = func() time.Time { return t0.Add(time.Minute) }
			tr.relay.source = fakePods{gatewayIP: {Namespace: "gateway", Name: "relay-x", UID: "gw"}}
			req := request(tc.host, gatewayIP+":1", http.Header{defaultHeader: {"Bearer forged"}})
			action, ann := runCtx(t, tr, transform.WithRelayPeer(context.Background(), tc.peer), req)
			if tc.token == "" {
				require.Equal(t, transform.ActionReject, action)
				require.Equal(t, "relay_peer_mismatch", ann["rejected"])
				require.Empty(t, req.Header.Get(defaultHeader))
				require.Zero(t, f.calls)
			} else {
				require.Equal(t, transform.ActionContinue, action)
				require.Equal(t, "Bearer "+tc.token, req.Header.Get(defaultHeader))
				require.Equal(t, tc.audience, f.lastAud)
			}
		})
	}
}

func TestRelayWithoutConfigNeverFallsBackToSourceIP(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f) // no relay config
	r := request("executor.mcp.local", "10.0.0.1:1", nil)
	act, ann := runCtx(t, tr, transform.WithRelayPeer(context.Background(), axPeer), r)
	require.Equal(t, transform.ActionReject, act)
	require.Equal(t, "relay_not_configured", ann["rejected"])
	require.Equal(t, 0, f.calls)
}

func TestRelayConfigValidation(t *testing.T) {
	src := relaySourceConfig{Namespaces: []string{"ate-system"}, LabelSelector: "app=atenet-egress"}
	base := config{TrustDomain: "sbx.interval.internal", IDPrefix: "/sandbox/", Routes: []routeConfig{{Audience: "a", Rules: []hostmatch.RuleConfig{{Host: "x"}}}}}
	cases := []struct {
		name  string
		relay relayConfig
	}{
		{"unanchored", relayConfig{IDPattern: `spiffe://x/(.+)`, SelectorType: "sbx", Source: src}},
		{"no capture", relayConfig{IDPattern: `^spiffe://x/.+$`, SelectorType: "sbx", Source: src}},
		{"two captures", relayConfig{IDPattern: `^spiffe://(x)/(.+)$`, SelectorType: "sbx", Source: src}},
		{"no selector type", relayConfig{IDPattern: `^spiffe://x/(.+)$`}},
		{"no source", relayConfig{IDPattern: `^spiffe://x/(.+)$`, SelectorType: "sbx"}},
		{"bad regex", relayConfig{IDPattern: `^spiffe://x/((.+)$`, SelectorType: "sbx", Source: src}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pods, f := setup()
			c := base
			rc := tc.relay
			c.Relay = &rc
			_, err := newFromConfig(c, slog.Default(), pods, f)
			require.Error(t, err)
		})
	}
}

func TestRelayFromUntrustedSourceIsRefused(t *testing.T) {
	tr, f := newRelayTransform(t)
	// A Kata guest (10.0.0.1) that somehow reached the relay listener and sent
	// a PROXY header naming an AX actor gets nothing.
	r := request("router.local", "10.0.0.1:1", nil)
	act, ann := runCtx(t, tr, transform.WithRelayPeer(context.Background(), axPeer), r)
	require.Equal(t, transform.ActionReject, act)
	require.Equal(t, "relay_source_untrusted", ann["rejected"])
	require.Empty(t, r.Header.Get(defaultHeader))
	require.Equal(t, 0, f.calls)
}

func TestRelayWaitsForPropagatingEntry(t *testing.T) {
	tr, f := newRelayTransform(t)
	tr.wait = 3 * time.Second
	f.pending = 2 // entry reaches the agent on the third poll
	r := request("router.local", gatewayIP+":1", nil)
	start := time.Now()
	act, ann := runCtx(t, tr, transform.WithRelayPeer(context.Background(), axPeer), r)
	require.Equal(t, transform.ActionContinue, act)
	require.Equal(t, "Bearer tok-ax", r.Header.Get(defaultHeader))
	require.NotNil(t, ann["spiffe_id"])
	require.Equal(t, 3, f.calls)
	require.Less(t, time.Since(start), 3*time.Second)
}

func TestRelayWaitIsBoundedAndOnlyForNotIssued(t *testing.T) {
	cases := []struct {
		name      string
		wait      time.Duration
		pending   int
		otherErr  error
		wantCalls int
	}{
		{"no wait configured", 0, 100, nil, 1},
		{"gives up after wait", 1200 * time.Millisecond, 100, nil, 3}, // polls at 0, 0.5 s, 1.0 s; no poll past the deadline
		{"other errors never wait", 3 * time.Second, 0, status.Error(codes.Unavailable, "agent down"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, f := newRelayTransform(t)
			tr.wait = tc.wait
			f.pending = tc.pending
			f.otherErr = tc.otherErr
			r := request("router.local", gatewayIP+":1", nil)
			act, ann := runCtx(t, tr, transform.WithRelayPeer(context.Background(), axPeer), r)
			require.Equal(t, transform.ActionReject, act)
			require.Equal(t, "svid_unavailable", ann["rejected"])
			require.Equal(t, tc.wantCalls, f.calls)
		})
	}
}

func TestRelayWaitBoundsStalledRPC(t *testing.T) {
	tr, f := newRelayTransform(t)
	tr.wait = 700 * time.Millisecond
	f.stall = true
	r := request("router.local", gatewayIP+":1", nil)
	start := time.Now()
	act, ann := runCtx(t, tr, transform.WithRelayPeer(context.Background(), axPeer), r)
	require.Equal(t, transform.ActionReject, act)
	require.Equal(t, "svid_unavailable", ann["rejected"])
	require.Less(t, time.Since(start), 1500*time.Millisecond, "a stalled RPC must not outlast wait")
}

func TestRelayWaitStopsOnClientCancel(t *testing.T) {
	tr, f := newRelayTransform(t)
	tr.wait = 10 * time.Second
	f.pending = 1000
	ctx, cancel := context.WithTimeout(transform.WithRelayPeer(context.Background(), axPeer), 600*time.Millisecond)
	defer cancel()
	r := request("router.local", gatewayIP+":1", nil)
	start := time.Now()
	act, ann := runCtx(t, tr, ctx, r)
	require.Equal(t, transform.ActionReject, act)
	require.Equal(t, "svid_unavailable", ann["rejected"])
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestRelayMultipleSVIDsRefusedWithoutWaiting(t *testing.T) {
	tr, f := newRelayTransform(t)
	tr.wait = 3 * time.Second
	f.bySel["sbx:ax-actor:sbx-abc123"] = []SVID{
		svid("spiffe://sbx.interval.internal/sandbox/ax/sbx-abc123/i/x", "t1"),
		svid("spiffe://sbx.interval.internal/sandbox/ax/sbx-abc123/i/y", "t2"),
	}
	r := request("router.local", gatewayIP+":1", nil)
	act, ann := runCtx(t, tr, transform.WithRelayPeer(context.Background(), axPeer), r)
	require.Equal(t, transform.ActionReject, act)
	require.Equal(t, "svid_unavailable", ann["rejected"])
	require.Equal(t, 1, f.calls)
	require.Empty(t, r.Header.Get(defaultHeader))
}

func TestPodPathWaitsForPropagatingEntry(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	tr.wait = 3 * time.Second
	f.podPending = 2 // a fresh guest's pod entry reaches the agent on the third poll
	r := request("executor.mcp.local", "10.0.0.1:1", nil)
	act, ann := run(t, tr, transform.ModeMITM, r)
	require.Equal(t, transform.ActionContinue, act)
	require.Equal(t, "Bearer tok-a", r.Header.Get(defaultHeader))
	require.Equal(t, "uid-a", ann["pod_uid"])
	require.Equal(t, 3, f.calls)
}

func TestPodPathWithoutEntryStillRefusedAfterWait(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	tr.wait = 1200 * time.Millisecond
	r := request("executor.mcp.local", "10.0.0.3:1", nil) // uid-c never has an entry
	start := time.Now()
	act, ann := run(t, tr, transform.ModeMITM, r)
	require.Equal(t, transform.ActionReject, act)
	require.Equal(t, "svid_unavailable", ann["rejected"])
	require.Equal(t, 3, f.calls)
	require.Less(t, time.Since(start), 2*time.Second)
}

func TestWaitConfigBounds(t *testing.T) {
	pods, f := setup()
	base := config{TrustDomain: "sbx.interval.internal", IDPrefix: "/sandbox/", Routes: []routeConfig{{Audience: "a", Rules: []hostmatch.RuleConfig{{Host: "x"}}}}}
	for _, w := range []time.Duration{-time.Second, 16 * time.Second} {
		c := base
		c.Wait = w
		_, err := newFromConfig(c, slog.Default(), pods, f)
		require.Error(t, err, w)
	}
	c := base
	c.Wait = 6 * time.Second
	tr, err := newFromConfig(c, slog.Default(), pods, f)
	require.NoError(t, err)
	require.Equal(t, 6*time.Second, tr.wait)
}
