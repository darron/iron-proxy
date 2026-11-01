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
	lastSel []*types.Selector
	lastAud string
}

func (f *fakeFetcher) FetchJWTSVIDs(_ context.Context, aud string, sel []*types.Selector) ([]SVID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastSel, f.lastAud = sel, aud
	if len(sel) != 1 || sel[0].Type != "k8s" || !strings.HasPrefix(sel[0].Value, "pod-uid:") {
		return nil, errors.New("bad selector")
	}
	s, ok := f.byUID[strings.TrimPrefix(sel[0].Value, "pod-uid:")]
	if !ok {
		return nil, errors.New("PermissionDenied: no identity issued")
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
		Audience:    "executor",
		TrustDomain: "sbx.interval.internal",
		IDPrefix:    "/sandbox/",
		Rules:       []hostmatch.RuleConfig{{Host: "executor.mcp.local"}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), pods, f)
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
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
	if act != transform.ActionContinue || ra.Header.Get(defaultHeader) != "Bearer tok-a" {
		t.Fatalf("A: action=%v header=%q", act, ra.Header.Get(defaultHeader))
	}
	if ann["spiffe_id"] != "spiffe://sbx.interval.internal/sandbox/kata/a" || ann["pod_uid"] != "uid-a" {
		t.Fatalf("A annotations: %v", ann)
	}
	for _, v := range ann {
		if s, ok := v.(string); ok && strings.Contains(s, "tok-") {
			t.Fatalf("token leaked into audit annotations: %v", ann)
		}
	}
	if f.lastAud != "executor" {
		t.Fatalf("audience %q", f.lastAud)
	}

	rb := request("executor.mcp.local", "10.0.0.2:41000", nil)
	if act, _ := run(t, tr, transform.ModeMITM, rb); act != transform.ActionContinue || rb.Header.Get(defaultHeader) != "Bearer tok-b" {
		t.Fatalf("B: action=%v header=%q", act, rb.Header.Get(defaultHeader))
	}
}

func TestForgedHeaderIsStrippedEverywhere(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	forged := http.Header{defaultHeader: {"Bearer tok-b"}}

	// Matching host: replaced with A's own identity.
	r := request("executor.mcp.local", "10.0.0.1:1", forged)
	run(t, tr, transform.ModeMITM, r)
	if got := r.Header.Values(defaultHeader); len(got) != 1 || got[0] != "Bearer tok-a" {
		t.Fatalf("matching host header = %v", got)
	}
	// Non-matching host: removed, nothing injected.
	r = request("example.com", "10.0.0.1:1", forged)
	act, ann := run(t, tr, transform.ModeMITM, r)
	if act != transform.ActionContinue || r.Header.Get(defaultHeader) != "" || ann["stripped"] == nil {
		t.Fatalf("non-matching: action=%v header=%q ann=%v", act, r.Header.Get(defaultHeader), ann)
	}
	// Rejected request: forged value must not survive either.
	r = request("executor.mcp.local", "10.0.0.50:1", forged)
	if act, _ := run(t, tr, transform.ModeMITM, r); act != transform.ActionReject || r.Header.Get(defaultHeader) != "" {
		t.Fatalf("unknown source: action=%v header=%q", act, r.Header.Get(defaultHeader))
	}
}

func TestFailsClosed(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	cases := map[string]struct {
		remote string
		mode   transform.Mode
		reason string
	}{
		"unknown ip":     {"10.0.0.50:1", transform.ModeMITM, "no_pod"},
		"ambiguous ip":   {"10.0.0.99:1", transform.ModeMITM, "ambiguous_pod"},
		"no entry":       {"10.0.0.3:1", transform.ModeMITM, "svid_unavailable"},
		"sni only":       {"10.0.0.1:1", transform.ModeSNIOnly, "mitm_required"},
		"bad remoteaddr": {"garbage", transform.ModeMITM, "bad_remote_addr"},
	}
	for name, c := range cases {
		r := request("executor.mcp.local", c.remote, nil)
		act, ann := run(t, tr, c.mode, r)
		if act != transform.ActionReject || ann["rejected"] != c.reason || r.Header.Get(defaultHeader) != "" {
			t.Errorf("%s: action=%v ann=%v header=%q", name, act, ann, r.Header.Get(defaultHeader))
		}
	}
}

func TestRejectsWrongTrustDomainOrMultipleSVIDs(t *testing.T) {
	pods, f := setup()
	f.byUID["uid-a"] = []SVID{svid("spiffe://evil.example/sandbox/kata/a", "tok")}
	f.byUID["uid-b"] = []SVID{svid("spiffe://sbx.interval.internal/sandbox/kata/b", "t1"), svid("spiffe://sbx.interval.internal/sandbox/kata/b2", "t2")}
	f.byUID["uid-c"] = []SVID{svid("spiffe://sbx.interval.internal/iron-proxy", "tok")}
	tr := newTestTransform(t, pods, f)
	for _, ip := range []string{"10.0.0.1:1", "10.0.0.2:1", "10.0.0.3:1"} {
		r := request("executor.mcp.local", ip, nil)
		if act, ann := run(t, tr, transform.ModeMITM, r); act != transform.ActionReject || ann["rejected"] != "svid_unavailable" {
			t.Errorf("%s: action=%v ann=%v", ip, act, ann)
		}
	}
}

func TestCacheRefreshAndRevocation(t *testing.T) {
	pods, f := setup()
	tr := newTestTransform(t, pods, f)
	clock := t0.Add(time.Minute)
	tr.now = func() time.Time { return clock }

	run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.1:1", nil))
	run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.1:1", nil))
	if f.calls != 1 {
		t.Fatalf("expected cached SVID before half-life, calls=%d", f.calls)
	}

	// Entry deleted on the SPIRE side; past half-life the next fetch fails and
	// the request is refused (no stale token is reused).
	delete(f.byUID, "uid-a")
	clock = t0.Add(3 * time.Minute)
	r := request("executor.mcp.local", "10.0.0.1:1", nil)
	if act, ann := run(t, tr, transform.ModeMITM, r); act != transform.ActionReject || ann["rejected"] != "svid_unavailable" {
		t.Fatalf("after entry deletion: action=%v ann=%v", act, ann)
	}

	// Pod deleted: resolver no longer maps the IP, refused immediately even
	// though B's token is cached.
	run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.2:1", nil))
	delete(pods, "10.0.0.2")
	if act, ann := run(t, tr, transform.ModeMITM, request("executor.mcp.local", "10.0.0.2:1", nil)); act != transform.ActionReject || ann["rejected"] != "no_pod" {
		t.Fatalf("after pod deletion: action=%v ann=%v", act, ann)
	}
}

func TestConfigValidation(t *testing.T) {
	pods, f := setup()
	base := config{Audience: "a", TrustDomain: "sbx.interval.internal", IDPrefix: "/sandbox/", Rules: []hostmatch.RuleConfig{{Host: "x"}}}
	bad := []func(c *config){
		func(c *config) { c.Audience = "" },
		func(c *config) { c.TrustDomain = "spiffe://sbx" },
		func(c *config) { c.IDPrefix = "/" },
		func(c *config) { c.IDPrefix = "sandbox" },
		func(c *config) { c.Rules = nil },
		func(c *config) { c.Header = "Proxy-Authorization" },
	}
	for i, mut := range bad {
		c := base
		mut(&c)
		if _, err := newFromConfig(c, slog.Default(), pods, f); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
	if _, err := newFromConfig(base, slog.Default(), pods, f); err != nil {
		t.Fatal(err)
	}
}

func TestKubePodResolver(t *testing.T) {
	var gotQuery, gotAuth string
	items := []map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery, gotAuth = r.URL.RawQuery, r.Header.Get("Authorization")
		if r.URL.Path != "/api/v1/namespaces/opensandbox-lab/pods" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	}))
	defer srv.Close()

	tokenFile := t.TempDir() + "/token"
	if err := writeFile(tokenFile, "sa-token\n"); err != nil {
		t.Fatal(err)
	}
	k := newKubePodResolverWithClient(kubeConfig{APIServer: srv.URL, TokenPath: tokenFile, Namespace: "opensandbox-lab", LabelSelector: "sbx-run", CacheTTL: time.Second}, srv.Client())
	clock := t0
	k.now = func() time.Time { return clock }

	pod := func(name, uid, ip string, mods ...func(m map[string]any)) map[string]any {
		m := map[string]any{
			"metadata": map[string]any{"name": name, "namespace": "opensandbox-lab", "uid": uid},
			"spec":     map[string]any{},
			"status":   map[string]any{"phase": "Running", "podIP": ip},
		}
		for _, mod := range mods {
			mod(m)
		}
		return m
	}

	items = []map[string]any{pod("sb-a", "uid-a", "10.0.0.1")}
	p, err := k.Resolve(context.Background(), "10.0.0.1")
	if err != nil || p.UID != "uid-a" {
		t.Fatalf("resolve: %v %v", p, err)
	}
	if gotAuth != "Bearer sa-token" || !strings.Contains(gotQuery, "fieldSelector=status.podIP%3D10.0.0.1%2Cstatus.phase%3DRunning") || !strings.Contains(gotQuery, "labelSelector=sbx-run") {
		t.Fatalf("query=%q auth=%q", gotQuery, gotAuth)
	}

	// Cached within TTL even if the pod disappears; refreshed after.
	items = nil
	if p, _ := k.Resolve(context.Background(), "10.0.0.1"); p.UID != "uid-a" {
		t.Fatal("expected cache hit")
	}
	clock = clock.Add(2 * time.Second)
	if _, err := k.Resolve(context.Background(), "10.0.0.1"); !errors.Is(err, ErrNoPod) {
		t.Fatalf("after TTL: %v", err)
	}

	// Local re-checks: terminating, hostNetwork, wrong IP, not Running are ignored.
	clock = clock.Add(2 * time.Second)
	items = []map[string]any{
		pod("del", "u1", "10.0.0.5", func(m map[string]any) { m["metadata"].(map[string]any)["deletionTimestamp"] = "2026-11-01T00:00:00Z" }),
		pod("host", "u2", "10.0.0.5", func(m map[string]any) { m["spec"] = map[string]any{"hostNetwork": true} }),
		pod("other", "u3", "10.0.0.6"),
		pod("pending", "u4", "10.0.0.5", func(m map[string]any) { m["status"].(map[string]any)["phase"] = "Pending" }),
	}
	if _, err := k.Resolve(context.Background(), "10.0.0.5"); !errors.Is(err, ErrNoPod) {
		t.Fatalf("filtered: %v", err)
	}

	clock = clock.Add(2 * time.Second)
	items = []map[string]any{pod("x", "u5", "10.0.0.7"), pod("y", "u6", "10.0.0.7")}
	if _, err := k.Resolve(context.Background(), "10.0.0.7"); !errors.Is(err, ErrAmbiguousPod) {
		t.Fatalf("ambiguous: %v", err)
	}
}

func writeFile(path, content string) error { return os.WriteFile(path, []byte(content), 0o600) }
