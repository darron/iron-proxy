package spiffejwtsvid

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIServer = "https://kubernetes.default.svc"
	defaultTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type kubeConfig struct {
	APIServer     string        `yaml:"api_server,omitempty"`
	TokenPath     string        `yaml:"token_path,omitempty"`
	CAPath        string        `yaml:"ca_path,omitempty"`
	Namespace     string        `yaml:"namespace"`
	LabelSelector string        `yaml:"label_selector"`
	CacheTTL      time.Duration `yaml:"cache_ttl,omitempty"`
}

// kubePodResolver looks a source IP up with a field-selected pod list:
// one Running, non-terminating, non-hostNetwork pod in the namespace,
// matching the label selector, whose status.podIP is the IP. Results
// (including misses) are cached for CacheTTL, which bounds how long a
// deleted pod can still resolve.
type kubePodResolver struct {
	cfg    kubeConfig
	client *http.Client
	now    func() time.Time

	mu    sync.Mutex
	cache map[string]cachedPod
}

type cachedPod struct {
	pod Pod
	err error
	at  time.Time
}

func newKubePodResolver(c kubeConfig) (*kubePodResolver, error) {
	if c.Namespace == "" {
		return nil, fmt.Errorf("\"kubernetes.namespace\" is required")
	}
	if c.LabelSelector == "" {
		return nil, fmt.Errorf("\"kubernetes.label_selector\" is required (scope lookups to sandbox pods)")
	}
	if c.APIServer == "" {
		c.APIServer = defaultAPIServer
	}
	if c.TokenPath == "" {
		c.TokenPath = defaultTokenPath
	}
	if c.CAPath == "" {
		c.CAPath = defaultCAPath
	}
	if c.CacheTTL <= 0 {
		c.CacheTTL = defaultPodCacheTTL
	}
	if c.CacheTTL > 30*time.Second {
		return nil, fmt.Errorf("\"kubernetes.cache_ttl\" must be at most 30s")
	}
	caPEM, err := os.ReadFile(c.CAPath)
	if err != nil {
		return nil, fmt.Errorf("reading Kubernetes CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates in Kubernetes CA %q", c.CAPath)
	}
	return newKubePodResolverWithClient(c, &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}), nil
}

func newKubePodResolverWithClient(c kubeConfig, client *http.Client) *kubePodResolver {
	if c.CacheTTL <= 0 {
		c.CacheTTL = defaultPodCacheTTL
	}
	return &kubePodResolver{cfg: c, client: client, now: time.Now, cache: make(map[string]cachedPod)}
}

type podList struct {
	Items []struct {
		Metadata struct {
			Name              string  `json:"name"`
			Namespace         string  `json:"namespace"`
			UID               string  `json:"uid"`
			DeletionTimestamp *string `json:"deletionTimestamp"`
		} `json:"metadata"`
		Spec struct {
			HostNetwork bool `json:"hostNetwork"`
		} `json:"spec"`
		Status struct {
			Phase  string `json:"phase"`
			PodIP  string `json:"podIP"`
			PodIPs []struct {
				IP string `json:"ip"`
			} `json:"podIPs"`
		} `json:"status"`
	} `json:"items"`
}

func (k *kubePodResolver) Resolve(ctx context.Context, ip string) (Pod, error) {
	now := k.now()
	k.mu.Lock()
	if c, ok := k.cache[ip]; ok && now.Sub(c.at) < k.cfg.CacheTTL {
		k.mu.Unlock()
		return c.pod, c.err
	}
	k.mu.Unlock()

	pod, err := k.lookup(ctx, ip)
	if err == nil || err == ErrNoPod || err == ErrAmbiguousPod {
		k.mu.Lock()
		k.cache[ip] = cachedPod{pod: pod, err: err, at: now}
		// Bound memory: drop expired entries opportunistically.
		for key, c := range k.cache {
			if now.Sub(c.at) >= k.cfg.CacheTTL {
				delete(k.cache, key)
			}
		}
		k.mu.Unlock()
	}
	return pod, err
}

func (k *kubePodResolver) lookup(ctx context.Context, ip string) (Pod, error) {
	q := url.Values{}
	q.Set("labelSelector", k.cfg.LabelSelector)
	q.Set("fieldSelector", "status.podIP="+ip+",status.phase=Running")
	u := strings.TrimRight(k.cfg.APIServer, "/") + "/api/v1/namespaces/" + url.PathEscape(k.cfg.Namespace) + "/pods?" + q.Encode()

	token, err := os.ReadFile(k.cfg.TokenPath)
	if err != nil {
		return Pod{}, fmt.Errorf("reading service account token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Pod{}, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	resp, err := k.client.Do(req)
	if err != nil {
		return Pod{}, fmt.Errorf("listing pods: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Pod{}, fmt.Errorf("reading pod list: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Pod{}, fmt.Errorf("listing pods: HTTP %d", resp.StatusCode)
	}
	var list podList
	if err := json.Unmarshal(body, &list); err != nil {
		return Pod{}, fmt.Errorf("decoding pod list: %w", err)
	}

	var found []Pod
	for _, it := range list.Items {
		// Re-check every condition locally; never trust the field selector alone.
		if it.Spec.HostNetwork || it.Metadata.DeletionTimestamp != nil || it.Status.Phase != "Running" || it.Metadata.UID == "" {
			continue
		}
		if !hasIP(it.Status.PodIP, it.Status.PodIPs, ip) {
			continue
		}
		found = append(found, Pod{Namespace: it.Metadata.Namespace, Name: it.Metadata.Name, UID: it.Metadata.UID})
	}
	switch len(found) {
	case 0:
		return Pod{}, ErrNoPod
	case 1:
		return found[0], nil
	default:
		return Pod{}, ErrAmbiguousPod
	}
}

func hasIP(primary string, all []struct {
	IP string `json:"ip"`
}, ip string) bool {
	if primary == ip {
		return true
	}
	for _, p := range all {
		if p.IP == ip {
			return true
		}
	}
	return false
}
