// SPDX-License-Identifier: Apache-2.0

// Package hub is the client for the grc.store backend's publish-side HTTP
// surface: discovery, the trusted-publishing CI bearer, registry-token mint,
// the immutable-version preflight, and the two sync routes. Extracted from
// grcli's internal/hub and privateer-sdk's internal/oci so the two tools
// cannot drift on what the hub expects.
//
// Errors never name a tool. Callers wrap with auth.App.LoginHint().
package hub

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/revanite-io/grc-store-protocol/apierror"
	"github.com/revanite-io/grc-store-protocol/registrytoken"
	"github.com/revanite-io/grc-store-protocol/syncapi"
)

var (
	// ErrNoBearer is returned by the authenticated routes when the client
	// carries no hub bearer.
	ErrNoBearer = errors.New("hub bearer token is required")
	// ErrUnauthorized wraps a hub 401 — the bearer was rejected (usually an
	// expired login).
	ErrUnauthorized = errors.New("hub rejected the bearer token")
)

// Client is the typed wrapper around the hub's HTTP API. Bearer may be empty
// for the public routes (VersionExists, an anonymous pull token).
type Client struct {
	BaseURL string
	Bearer  string
	HTTP    *http.Client
}

// Timeout is the per-request timeout of a Client from New. It sits above
// the hub's longest sync deadline, plugin sync's 6-minute write deadline,
// and so also covers catalog and EvaluationLog sync (120 s). It is one
// timeout for every route of the client: the hub bounds each sync itself,
// so the longer wait costs nothing.
const Timeout = 7 * time.Minute

// New returns a Client with a request timeout of Timeout.
func New(baseURL, bearer string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Bearer:  bearer,
		HTTP:    &http.Client{Timeout: Timeout},
	}
}

// do issues one request and returns status + capped body. A non-nil error is
// a transport failure only; HTTP status is the caller's to interpret.
func (c *Client) do(ctx context.Context, method, path string, body any, withBearer bool) (int, []byte, error) {
	status, _, rb, err := c.doHeader(ctx, method, path, body, withBearer)
	return status, rb, err
}

// doHeader is do plus the response headers.
func (c *Client) doHeader(ctx context.Context, method, path string, body any, withBearer bool) (int, http.Header, []byte, error) {
	if c.BaseURL == "" {
		return 0, nil, nil, errors.New("hub base URL is required")
	}
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		rd = bytes.NewReader(data)
	}
	url := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("building request for %s: %w", url, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withBearer && c.Bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.Bearer)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, resp.Header, nil, fmt.Errorf("reading response from %s: %w", url, err)
	}
	return resp.StatusCode, resp.Header, rb, nil
}

// StatusError is an unexpected hub status: URL, status, the apierror code
// from the body ("" when the body is not an apierror.Envelope) and a capped
// body. Callers branch on it with errors.As; a 401 also matches
// ErrUnauthorized through errors.Is.
type StatusError struct {
	What   string // the route, as the message names it ("plugin sync")
	URL    string
	Status int
	Code   string // apierror code, e.g. "plugin_version_immutable"
	Body   []byte
}

func (e *StatusError) Error() string {
	msg := fmt.Sprintf("hub %s %s returned %d: %s", e.What, e.URL, e.Status, bytes.TrimSpace(e.Body))
	if e.Status == http.StatusUnauthorized {
		return ErrUnauthorized.Error() + ": " + msg // the text a 401 carried before StatusError
	}
	return msg
}

// Unwrap lets errors.Is(err, ErrUnauthorized) hold for a 401.
func (e *StatusError) Unwrap() error {
	if e.Status == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	return nil
}

// statusErr is the one diagnostic shape for an unexpected hub status:
// URL + status + body snippet, so a 5xx on any route reads the same.
func (c *Client) statusErr(what, path string, status int, body []byte) error {
	var env apierror.Envelope
	_ = json.Unmarshal(body, &env) // a non-envelope body leaves Code empty
	return &StatusError{What: what, URL: c.BaseURL + path, Status: status, Code: env.Error, Body: body}
}

// VersionStatus reports whether a (namespace, id, version) coordinate is
// already taken on the hub.
type VersionStatus int

const (
	// VersionAbsent — free to publish (hub 404).
	VersionAbsent VersionStatus = iota
	// VersionPresent — already published at this coordinate (hub 200).
	VersionPresent
	// VersionTombstoned — published then yanked (hub 410). Versions are
	// immutable, so the coordinate stays taken.
	VersionTombstoned
)

// VersionExists is the publish preflight for the immutable catalog
// coordinate, via GET /v1/catalogs/{ns}/{id}/versions/{version}. Public
// route; no bearer needed. It halts a publish BEFORE the registry write
// clobbers existing bytes. There is no EvaluationLog equivalent yet, so
// log publishers skip this.
func (c *Client) VersionExists(ctx context.Context, namespace, id, version string) (VersionStatus, error) {
	path := fmt.Sprintf("/v1/catalogs/%s/%s/versions/%s",
		neturl.PathEscape(namespace), neturl.PathEscape(id), neturl.PathEscape(version))
	status, body, err := c.do(ctx, http.MethodGet, path, nil, false)
	if err != nil {
		return VersionAbsent, err
	}
	switch status {
	case http.StatusOK:
		return VersionPresent, nil
	case http.StatusNotFound:
		return VersionAbsent, nil
	case http.StatusGone:
		return VersionTombstoned, nil
	default:
		return VersionAbsent, c.statusErr("version check", path, status, body)
	}
}

// Token is a short-lived OCI Distribution token minted by the hub, plus the
// actions the hub actually granted on the repository (decoded from the
// token's Docker-style `access` claim; read, not verified).
type Token struct {
	Token   string
	Actions []string
}

// GrantsPush reports whether the hub granted push. The hub returns a
// PULL-ONLY token (not an error) to a caller who does not own the
// namespace, so publishers must check this before packing anything.
func (t Token) GrantsPush() bool { return slices.Contains(t.Actions, "push") }

// RegistryToken exchanges the client's hub bearer for a registry token
// scoped to repository + actions via GET /v2/token. An empty bearer yields an
// anonymous pull token. The token is presented to the registry directly —
// the bearer realm is gated on a hub login the registry client cannot
// perform on its own.
func (c *Client) RegistryToken(ctx context.Context, repository string, actions []string) (Token, error) {
	if repository == "" {
		return Token{}, errors.New("repository is required to fetch a registry token")
	}
	if len(actions) == 0 {
		return Token{}, errors.New("at least one action (pull/push) is required")
	}
	q := neturl.Values{}
	q.Set("scope", "repository:"+repository+":"+strings.Join(actions, ","))
	q.Set("service", "zot") // informational; the hub sets the audience from its own config
	path := "/v2/token?" + q.Encode()

	status, body, err := c.do(ctx, http.MethodGet, path, nil, true)
	if err != nil {
		return Token{}, err
	}
	if status != http.StatusOK {
		return Token{}, c.statusErr("registry-token endpoint", path, status, body)
	}
	var tr registrytoken.Response
	if err := json.Unmarshal(body, &tr); err != nil {
		return Token{}, fmt.Errorf("decoding registry token: %w", err)
	}
	tok := tr.BearerToken()
	if tok == "" {
		return Token{}, errors.New("hub registry-token endpoint returned no token")
	}
	return Token{Token: tok, Actions: grantedActions(tok, repository)}, nil
}

func grantedActions(token, repo string) []string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		Access []struct {
			Type    string   `json:"type"`
			Name    string   `json:"name"`
			Actions []string `json:"actions"`
		} `json:"access"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	for _, e := range claims.Access {
		if e.Type == "repository" && e.Name == repo {
			return e.Actions
		}
	}
	return nil
}

// SyncBundle calls POST /v1/bundles/sync so the hub indexes a Gemara bundle
// already pushed to the registry. The hub fetches server-side; no bytes are
// re-uploaded.
func (c *Client) SyncBundle(ctx context.Context, repository, tag string) (*syncapi.Response, error) {
	if c.Bearer == "" {
		return nil, ErrNoBearer
	}
	const path = "/v1/bundles/sync"
	status, body, err := c.do(ctx, http.MethodPost, path, syncapi.Request{Repository: repository, Tag: tag}, true)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, c.statusErr("sync", path, status, body)
	}
	out := &syncapi.Response{}
	if err := json.Unmarshal(body, out); err != nil {
		return nil, fmt.Errorf("decoding hub sync response: %w", err)
	}
	return out, nil
}

// PluginRepository is the served registry repository a plugin's image index
// lives in: <namespace>/plugins/<id>. Publishers push to its staging form,
// staging.Repository(PluginRepository(ns, id)); only
// the hub writes the served one.
func PluginRepository(namespace, id string) string {
	return namespace + "/plugins/" + id
}

// MaxPluginSyncRetries bounds SyncPlugin's retries of a 503 that carries
// Retry-After: 12 waits of the hub's 60 s is two full plugin copy deadlines,
// enough for the third of three plugins in one namespace released together.
const MaxPluginSyncRetries = 12

// sleep is swapped by tests so a Retry-After wait does not take real time.
var sleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// SyncPlugin calls POST /v1/plugins/{ns}/{id}/sync for a plugin image index
// already pushed to the staging form of PluginRepository(ns, id) at tag. The
// request names the served repository; the hub derives the staging one,
// checks the upload there and promotes it.
//
// The hub refuses a promotion it has no slot for with 503 and Retry-After.
// SyncPlugin waits the given time and retries, at most MaxPluginSyncRetries
// times, then returns the last error. A 503 without Retry-After, or any
// other status, is returned at once.
func (c *Client) SyncPlugin(ctx context.Context, namespace, id, tag string) error {
	if c.Bearer == "" {
		return ErrNoBearer
	}
	path := fmt.Sprintf("/v1/plugins/%s/%s/sync", neturl.PathEscape(namespace), neturl.PathEscape(id))
	req := syncapi.Request{Repository: PluginRepository(namespace, id), Tag: tag}
	for attempt := 0; ; attempt++ {
		status, hdr, body, err := c.doHeader(ctx, http.MethodPost, path, req, true)
		if err != nil {
			return err
		}
		if status/100 == 2 {
			return nil
		}
		wait, ok := retryAfter(hdr, time.Now())
		if status != http.StatusServiceUnavailable || !ok || attempt == MaxPluginSyncRetries {
			return c.statusErr("plugin sync", path, status, body)
		}
		if err := sleep(ctx, wait); err != nil {
			return fmt.Errorf("waiting to retry plugin sync after %d: %w", status, err)
		}
	}
}

// MaxRetryAfter caps one SyncPlugin wait. The hub sends 60 s; a larger value
// (a proxy, a misconfigured hub) is clamped so the retries stay near the
// 12 minutes MaxPluginSyncRetries budgets instead of hanging a CI job.
const MaxRetryAfter = 2 * time.Minute

// retryAfter reads a Retry-After header, in delay-seconds or HTTP-date form
// (RFC 9110 §10.2.3), clamped to [0, MaxRetryAfter]. ok is false when it is
// absent or unparsable.
func retryAfter(h http.Header, now time.Time) (time.Duration, bool) {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0, false
		}
		// Compared in seconds first so a huge value cannot overflow Duration.
		if secs >= int64(MaxRetryAfter/time.Second) {
			return MaxRetryAfter, true
		}
		return time.Duration(secs) * time.Second, true
	}
	if at, err := http.ParseTime(v); err == nil {
		return min(max(at.Sub(now), 0), MaxRetryAfter), true
	}
	return 0, false
}
