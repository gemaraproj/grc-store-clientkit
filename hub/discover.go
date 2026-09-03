// SPDX-License-Identifier: Apache-2.0

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/gemaraproj/grc-store-clientkit/auth"
	"github.com/revanite-io/grc-store-protocol/discovery"
)

// WellKnownPath is appended to the hub base URL (RFC 8615 §3).
const WellKnownPath = "/.well-known/grc-store-configuration"

// discoveryCache holds one document per normalized base URL for the process
// lifetime: discovery is called from several steps of one publish and must
// not cost a round-trip each time.
var discoveryCache sync.Map // map[string]*discovery.Document

// Discover fetches the hub's well-known discovery document. registry_url
// must be present; everything else is optional. Cached per normalized
// baseURL.
func Discover(ctx context.Context, baseURL string) (*discovery.Document, error) {
	key := strings.TrimRight(baseURL, "/")
	if key == "" {
		return nil, errors.New("hub base URL is required")
	}
	if cached, ok := discoveryCache.Load(key); ok {
		return cached.(*discovery.Document), nil
	}

	url := key + WellKnownPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building discovery request for %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hub discovery at %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	d := &discovery.Document{}
	if err := json.Unmarshal(body, d); err != nil {
		return nil, fmt.Errorf("decoding hub discovery at %s: %w (body: %s)", url, err, strings.TrimSpace(string(body)))
	}
	if strings.TrimSpace(d.RegistryURL) == "" {
		return nil, fmt.Errorf("hub discovery at %s did not advertise registry_url; the hub is misconfigured (HUB_OCI_PUBLIC_URL must be set)", url)
	}
	discoveryCache.Store(key, d)
	return d, nil
}

func resetDiscoveryCacheForTest() {
	discoveryCache.Range(func(k, _ any) bool { discoveryCache.Delete(k); return true })
}

// Registry parses the advertised registry_url into the bare host an OCI
// reference wants (<host>/<repo>:<tag>) and whether the registry speaks
// plain HTTP. A bare host with no scheme implies https. One parse feeds
// both answers so they cannot contradict each other.
func Registry(d *discovery.Document) (host string, plainHTTP bool, err error) {
	raw := strings.TrimSpace(d.RegistryURL)
	if raw == "" {
		return "", false, errors.New("registry_url is empty")
	}
	if !strings.Contains(raw, "://") {
		return strings.TrimRight(raw, "/"), false, nil
	}
	u, err := neturl.Parse(raw)
	if err != nil {
		return "", false, fmt.Errorf("parsing registry_url %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", false, fmt.Errorf("registry_url %q has no host", raw)
	}
	return u.Host, u.Scheme == "http", nil
}

// CIBearer is the trusted-publishing bearer: inside GitHub Actions, the
// workflow's OIDC token minted with the hub's advertised ci_audience (falling
// back to the hub URL when discovery omits it) is presented directly as the
// hub bearer. The hub maps the workflow's repository to its trusted-publisher
// namespace, so CI publishes with no stored secret. ok is false outside
// GitHub Actions; callers then fall through to auth.Resolve.
func CIBearer(ctx context.Context, hubURL string, d *discovery.Document) (tok string, ok bool, err error) {
	if !auth.InGitHubActions() {
		return "", false, nil
	}
	aud := strings.TrimRight(hubURL, "/")
	if d != nil && d.CIAudience != "" {
		aud = d.CIAudience
	}
	tok, err = auth.FetchGitHubActionsToken(ctx, aud)
	if err != nil {
		return "", true, err
	}
	return tok, true, nil
}
