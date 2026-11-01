// Package spiffejwtsvid implements a transform that attaches the calling
// sandbox's SPIFFE JWT-SVID to matching requests.
//
// The workload (for example a Kata guest) never holds the SVID. iron-proxy,
// outside the guest, maps the connection's source IP to exactly one running
// Kubernetes pod, then asks the local SPIRE agent's Delegated Identity API
// (admin socket) for a JWT-SVID issued to that pod's registration entry,
// selected by `k8s:pod-uid:<uid>`. Any client-supplied copy of the header is
// removed on every request, matching or not, so a workload cannot forge an
// identity.
//
// The proxy must be listed in the SPIRE agent's `authorized_delegates`.
//
// Like all header-injecting transforms, injection requires MITM mode.
package spiffejwtsvid

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

const (
	name                = "spiffe_jwt_svid"
	defaultHeader       = "X-Sbx-Identity"
	defaultPodCacheTTL  = 2 * time.Second
	defaultFetchTimeout = 5 * time.Second
)

func init() {
	transform.Register(name, factory)
}

type config struct {
	AdminSocket string        `yaml:"admin_socket"`
	Header      string        `yaml:"header,omitempty"`
	TrustDomain string        `yaml:"trust_domain"`
	IDPrefix    string        `yaml:"id_prefix"`
	Mode        string        `yaml:"mode,omitempty"`
	Kubernetes  kubeConfig    `yaml:"kubernetes"`
	Routes      []routeConfig `yaml:"routes"`
	Relay       *relayConfig  `yaml:"relay,omitempty"`
}

// relayConfig handles requests that arrived on iron-proxy's trusted relay
// listener, where a gateway (not the source IP) asserts who the workload is.
// IDPattern must match the whole asserted identity and capture exactly one
// group; the SVID is fetched for selector SelectorType:SelectorPrefix+group.
type relayConfig struct {
	IDPattern      string `yaml:"id_pattern"`
	SelectorType   string `yaml:"selector_type"`
	SelectorPrefix string `yaml:"selector_prefix"`
}

type relay struct {
	re             *regexp.Regexp
	selectorType   string
	selectorPrefix string
}

// routeConfig binds a set of destinations to one JWT audience, so a token
// minted for one upstream is not accepted by another.
type routeConfig struct {
	Audience string                 `yaml:"audience"`
	Rules    []hostmatch.RuleConfig `yaml:"rules"`
}

type route struct {
	audience string
	rules    []hostmatch.Rule
}

// Pod is the minimal view of the pod that owns a source IP.
type Pod struct {
	Namespace string
	Name      string
	UID       string
}

// PodResolver maps a source IP to the single running pod that owns it.
// It returns ErrNoPod when no eligible pod owns the IP and ErrAmbiguousPod
// when more than one does.
type PodResolver interface {
	Resolve(ctx context.Context, ip string) (Pod, error)
}

var (
	ErrNoPod        = errors.New("no eligible pod owns the source IP")
	ErrAmbiguousPod = errors.New("more than one eligible pod owns the source IP")
)

// SVID is a fetched JWT-SVID. Token is secret and must never be logged.
type SVID struct {
	Token     string
	SPIFFEID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// SVIDFetcher fetches JWT-SVIDs for a workload described by selectors.
type SVIDFetcher interface {
	FetchJWTSVIDs(ctx context.Context, audience string, selectors []*types.Selector) ([]SVID, error)
}

// Transform is the spiffe_jwt_svid transform.
type Transform struct {
	routes      []route
	header      string
	trustDomain string
	idPrefix    string
	observe     bool
	relay       *relay
	pods        PodResolver
	fetcher     SVIDFetcher
	now         func() time.Time
	logger      *slog.Logger

	mu    sync.Mutex
	cache map[cacheKey]SVID
}

func factory(cfg yaml.Node, logger *slog.Logger) (transform.Transformer, error) {
	var c config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing %s config: %w", name, err)
	}
	if c.AdminSocket == "" {
		return nil, fmt.Errorf("%s: \"admin_socket\" is required", name)
	}
	pods, err := newKubePodResolver(c.Kubernetes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	fetcher, err := newDelegatedFetcher(c.AdminSocket)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return newFromConfig(c, logger, pods, fetcher)
}

func newFromConfig(c config, logger *slog.Logger, pods PodResolver, fetcher SVIDFetcher) (*Transform, error) {
	if c.TrustDomain == "" || strings.ContainsAny(c.TrustDomain, "/:") {
		return nil, fmt.Errorf("%s: \"trust_domain\" is required and must be a bare trust domain name", name)
	}
	if !strings.HasPrefix(c.IDPrefix, "/") || !strings.HasSuffix(c.IDPrefix, "/") || len(c.IDPrefix) < 3 {
		return nil, fmt.Errorf("%s: \"id_prefix\" must be a path like \"/sandbox/\"", name)
	}
	if len(c.Routes) == 0 {
		return nil, fmt.Errorf("%s: at least one entry in \"routes\" is required", name)
	}
	routes := make([]route, 0, len(c.Routes))
	for i, rc := range c.Routes {
		if rc.Audience == "" {
			return nil, fmt.Errorf("%s: routes[%d] needs an \"audience\"", name, i)
		}
		rules, err := hostmatch.CompileRules(rc.Rules, name)
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("%s: routes[%d] needs at least one entry in \"rules\"", name, i)
		}
		routes = append(routes, route{audience: rc.Audience, rules: rules})
	}
	header := http.CanonicalHeaderKey(strings.TrimSpace(c.Header))
	if header == "" {
		header = defaultHeader
	}
	switch strings.ToLower(header) {
	case "host", "proxy-authorization", "cookie", "content-length", "transfer-encoding":
		return nil, fmt.Errorf("%s: \"header\" %q is not allowed", name, header)
	}
	var observe bool
	switch c.Mode {
	case "", "enforce":
	case "observe":
		observe = true
	default:
		return nil, fmt.Errorf("%s: \"mode\" must be \"enforce\" or \"observe\"", name)
	}
	var rl *relay
	if c.Relay != nil {
		if !strings.HasPrefix(c.Relay.IDPattern, "^") || !strings.HasSuffix(c.Relay.IDPattern, "$") {
			return nil, fmt.Errorf("%s: relay.id_pattern must be anchored with ^ and $", name)
		}
		re, err := regexp.Compile(c.Relay.IDPattern)
		if err != nil {
			return nil, fmt.Errorf("%s: relay.id_pattern: %w", name, err)
		}
		if re.NumSubexp() != 1 {
			return nil, fmt.Errorf("%s: relay.id_pattern must capture exactly one group", name)
		}
		if c.Relay.SelectorType == "" || strings.Contains(c.Relay.SelectorType, ":") {
			return nil, fmt.Errorf("%s: relay.selector_type is required and must not contain ':'", name)
		}
		rl = &relay{re: re, selectorType: c.Relay.SelectorType, selectorPrefix: c.Relay.SelectorPrefix}
	}
	return &Transform{
		routes:      routes,
		header:      header,
		trustDomain: c.TrustDomain,
		idPrefix:    c.IDPrefix,
		observe:     observe,
		relay:       rl,
		pods:        pods,
		fetcher:     fetcher,
		now:         time.Now,
		logger:      logger,
		cache:       make(map[cacheKey]SVID),
	}, nil
}

func (t *Transform) Name() string { return name }

// unidentified handles a matching request that cannot carry an identity.
// In enforce mode it is refused. In observe mode it continues without the
// header (any client copy was already stripped), for rollouts where some
// sources (for example traffic relayed by another lane's gateway) have no
// pod identity yet.
func (t *Transform) unidentified(tctx *transform.TransformContext, reason string) (*transform.TransformResult, error) {
	if t.observe {
		tctx.Annotate("unidentified", reason)
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	tctx.Annotate("rejected", reason)
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (t *Transform) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	// Never let a workload supply its own identity, on any request.
	if _, forged := req.Header[t.header]; forged {
		req.Header.Del(t.header)
		tctx.Annotate("stripped", []string{"header:" + t.header})
	}

	// A CONNECT only opens a tunnel; each request inside it passes through
	// this transform again and carries the identity there.
	if req.Method == http.MethodConnect {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	audience, ok := t.audienceFor(req)
	if !ok {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if tctx.Mode != transform.ModeMITM {
		return t.unidentified(tctx, "mitm_required")
	}
	// A request relayed by a trusted gateway is identified by what that
	// gateway asserted, never by the source IP (the gateway's own address).
	if peer, ok := transform.RelayPeer(ctx); ok {
		return t.relayIdentity(ctx, tctx, req, audience, peer)
	}

	ip, err := sourceIP(req.RemoteAddr)
	if err != nil {
		return t.unidentified(tctx, "bad_remote_addr")
	}
	pod, err := t.pods.Resolve(ctx, ip)
	switch {
	case errors.Is(err, ErrNoPod):
		return t.unidentified(tctx, "no_pod")
	case errors.Is(err, ErrAmbiguousPod):
		return t.unidentified(tctx, "ambiguous_pod")
	case err != nil:
		t.logger.Warn("spiffe_jwt_svid: pod lookup failed", slog.String("error", err.Error()))
		return t.unidentified(tctx, "pod_lookup_failed")
	}

	svid, err := t.svidFor(ctx, "pod:"+pod.UID, &types.Selector{Type: "k8s", Value: "pod-uid:" + pod.UID}, audience)
	if err != nil {
		t.logger.Warn("spiffe_jwt_svid: no svid", slog.String("pod_uid", pod.UID), slog.String("error", err.Error()))
		return t.unidentified(tctx, "svid_unavailable")
	}

	req.Header.Set(t.header, "Bearer "+svid.Token)
	tctx.Annotate("spiffe_id", svid.SPIFFEID)
	tctx.Annotate("pod", pod.Namespace+"/"+pod.Name)
	tctx.Annotate("pod_uid", pod.UID)
	tctx.Annotate("audience", audience)
	tctx.Annotate("injected", []string{"header:" + t.header})
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (t *Transform) relayIdentity(ctx context.Context, tctx *transform.TransformContext, req *http.Request, audience, peer string) (*transform.TransformResult, error) {
	if t.relay == nil {
		return t.unidentified(tctx, "relay_not_configured")
	}
	m := t.relay.re.FindStringSubmatch(peer)
	if m == nil || m[1] == "" {
		return t.unidentified(tctx, "relay_peer_mismatch")
	}
	sel := &types.Selector{Type: t.relay.selectorType, Value: t.relay.selectorPrefix + m[1]}
	svid, err := t.svidFor(ctx, "relay:"+sel.Type+":"+sel.Value, sel, audience)
	if err != nil {
		t.logger.Warn("spiffe_jwt_svid: no svid for relayed peer", slog.String("peer", peer), slog.String("error", err.Error()))
		return t.unidentified(tctx, "svid_unavailable")
	}
	req.Header.Set(t.header, "Bearer "+svid.Token)
	tctx.Annotate("spiffe_id", svid.SPIFFEID)
	tctx.Annotate("relay_peer", peer)
	tctx.Annotate("audience", audience)
	tctx.Annotate("injected", []string{"header:" + t.header})
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (t *Transform) TransformResponse(context.Context, *transform.TransformContext, *http.Request, *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

// audienceFor returns the audience of the first route matching req.
func (t *Transform) audienceFor(req *http.Request) (string, bool) {
	for _, r := range t.routes {
		if hostmatch.MatchAnyRule(r.rules, req) {
			return r.audience, true
		}
	}
	return "", false
}

// cacheKey identifies a cached SVID: the workload subject ("pod:<uid>" or
// "relay:<selector>") and the audience it was minted for.
type cacheKey struct{ subject, audience string }

// svidFor returns a cached SVID until half its lifetime has passed, then
// fetches a fresh one. A fetch failure evicts the cache entry, so deleting
// the registration entry stops injection at the next refresh at the latest.
// Expired entries (for example of deleted pods) are pruned on every store.
func (t *Transform) svidFor(ctx context.Context, subject string, selector *types.Selector, audience string) (SVID, error) {
	now := t.now()
	key := cacheKey{subject, audience}
	t.mu.Lock()
	cached, ok := t.cache[key]
	t.mu.Unlock()
	if ok && now.Before(cached.IssuedAt.Add(cached.ExpiresAt.Sub(cached.IssuedAt)/2)) {
		return cached, nil
	}

	fctx, cancel := context.WithTimeout(ctx, defaultFetchTimeout)
	defer cancel()
	svids, err := t.fetcher.FetchJWTSVIDs(fctx, audience, []*types.Selector{selector})
	if err == nil {
		var svid SVID
		svid, err = t.pickSVID(svids, now)
		if err == nil {
			t.mu.Lock()
			for k, v := range t.cache {
				if !v.ExpiresAt.After(now) {
					delete(t.cache, k)
				}
			}
			t.cache[key] = svid
			t.mu.Unlock()
			return svid, nil
		}
	}
	t.mu.Lock()
	delete(t.cache, key)
	t.mu.Unlock()
	return SVID{}, err
}

func (t *Transform) pickSVID(svids []SVID, now time.Time) (SVID, error) {
	if len(svids) != 1 {
		return SVID{}, fmt.Errorf("expected exactly one JWT-SVID, got %d", len(svids))
	}
	s := svids[0]
	want := "spiffe://" + t.trustDomain + t.idPrefix
	if !strings.HasPrefix(s.SPIFFEID, want) || len(s.SPIFFEID) == len(want) {
		return SVID{}, fmt.Errorf("SPIFFE ID %q is outside %q", s.SPIFFEID, want)
	}
	if s.Token == "" || !s.ExpiresAt.After(now) || !s.ExpiresAt.After(s.IssuedAt) {
		return SVID{}, errors.New("JWT-SVID is empty or expired")
	}
	return s, nil
}

func sourceIP(remoteAddr string) (string, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("remote address %q is not an IP", remoteAddr)
	}
	return ip.String(), nil
}

// delegatedFetcher calls the SPIRE agent Delegated Identity API.
type delegatedFetcher struct {
	client delegatedidentityv1.DelegatedIdentityClient
}

func newDelegatedFetcher(socket string) (*delegatedFetcher, error) {
	if !strings.HasPrefix(socket, "/") {
		return nil, fmt.Errorf("\"admin_socket\" must be an absolute Unix socket path")
	}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dialing SPIRE agent admin socket: %w", err)
	}
	return &delegatedFetcher{client: delegatedidentityv1.NewDelegatedIdentityClient(conn)}, nil
}

func (d *delegatedFetcher) FetchJWTSVIDs(ctx context.Context, audience string, selectors []*types.Selector) ([]SVID, error) {
	resp, err := d.client.FetchJWTSVIDs(ctx, &delegatedidentityv1.FetchJWTSVIDsRequest{
		Audience:  []string{audience},
		Selectors: selectors,
	})
	if err != nil {
		return nil, err
	}
	out := make([]SVID, 0, len(resp.GetSvids()))
	for _, s := range resp.GetSvids() {
		id := s.GetId()
		out = append(out, SVID{
			Token:     s.GetToken(),
			SPIFFEID:  "spiffe://" + id.GetTrustDomain() + id.GetPath(),
			IssuedAt:  time.Unix(s.GetIssuedAt(), 0),
			ExpiresAt: time.Unix(s.GetExpiresAt(), 0),
		})
	}
	return out, nil
}
