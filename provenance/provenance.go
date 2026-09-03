// SPDX-License-Identifier: Apache-2.0

// Package provenance builds the SLSA v1 provenance predicate that a publish
// embeds (unsigned) in the bundle's config blob and signs as a second OCI
// referrer. Extracted from grcli's internal/provenance; the Evaluator
// sub-struct is the results-publishing addition that binds an
// EvaluationLog to the plugin that produced it.
package provenance

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	// PredicateType is the SLSA v1 provenance predicateType.
	PredicateType = "https://slsa.dev/provenance/v1"
	// BuildType identifies a grc.store client publish (no longer named for one tool).
	BuildType = "https://grc.store/buildtype/v0"
)

// Predicate is the SLSA v1 provenance predicate body.
type Predicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

type BuildDefinition struct {
	BuildType            string          `json:"buildType"`
	ExternalParameters   map[string]any  `json:"externalParameters,omitempty"`
	InternalParameters   map[string]any  `json:"internalParameters,omitempty"`
	ResolvedDependencies []ResourceDescr `json:"resolvedDependencies,omitempty"`
}

type RunDetails struct {
	Builder    Builder         `json:"builder"`
	Metadata   Metadata        `json:"metadata"`
	Byproducts []ResourceDescr `json:"byproducts,omitempty"`
}

type Builder struct {
	ID                  string            `json:"id"`
	Version             map[string]string `json:"version,omitempty"`
	BuilderDependencies []ResourceDescr   `json:"builderDependencies,omitempty"`
}

type Metadata struct {
	InvocationID string    `json:"invocationId,omitempty"`
	StartedOn    time.Time `json:"startedOn"`
	FinishedOn   time.Time `json:"finishedOn,omitempty"`
}

type ResourceDescr struct {
	Name   string            `json:"name,omitempty"`
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// Evaluator binds a published EvaluationLog to the plugin that produced
// it: the hub coordinate and the published index digest (the verifiable
// half — claims are tied to the digest, never the tag), plus the target
// and run the log describes.
type Evaluator struct {
	Coordinate    string // <namespace>/<plugin-id>
	IndexDigest   string // sha256:<hex> of the plugin's published image index
	TargetID      string
	TargetVersion string
	RunID         string
}

// Input is what Build needs. Tool/ToolVersion name the publishing client
// (e.g. "grcli", "pvtr") in the builder version map.
type Input struct {
	Tool           string
	ToolVersion    string
	StartedOn      time.Time
	ArtifactType   string
	ArtifactID     string
	ArtifactName   string
	ArtifactDigest string            // sha256:<hex> of the bundle body
	SourceFiles    map[string]string // path -> sha256:<hex>
	Registry       string
	Repository     string
	Tag            string
	Evaluator      *Evaluator
}

// Build assembles the predicate. Environment-derived fields (builder id,
// GitHub Actions parameters, git source) are read at call time.
func Build(in Input) Predicate {
	builderID, builderVer := identifyBuilder(in.Tool, in.ToolVersion)

	external := map[string]any{
		"artifact": map[string]string{"type": in.ArtifactType, "id": in.ArtifactID},
		"target":   map[string]string{"registry": in.Registry, "repository": in.Repository, "tag": in.Tag},
	}

	resolved := make([]ResourceDescr, 0, len(in.SourceFiles)+2)
	for _, path := range sortedKeys(in.SourceFiles) {
		resolved = append(resolved, ResourceDescr{Name: path, URI: "file://" + path, Digest: digestMap(in.SourceFiles[path])})
	}
	if git := detectGit(); git != nil {
		resolved = append(resolved, *git)
	}
	if e := in.Evaluator; e != nil {
		external["evaluator"] = map[string]string{
			"coordinate": e.Coordinate, "target_id": e.TargetID, "target_version": e.TargetVersion, "run_id": e.RunID,
		}
		if e.IndexDigest != "" {
			resolved = append(resolved, ResourceDescr{Name: "evaluator", URI: "oci://" + in.Registry + "/" + e.Coordinate, Digest: digestMap(e.IndexDigest)})
		}
	}

	byproducts := []ResourceDescr{}
	if in.ArtifactDigest != "" {
		byproducts = append(byproducts, ResourceDescr{Name: in.ArtifactName, Digest: digestMap(in.ArtifactDigest)})
	}

	return Predicate{
		BuildDefinition: BuildDefinition{
			BuildType:            BuildType,
			ExternalParameters:   external,
			InternalParameters:   internalParams(),
			ResolvedDependencies: resolved,
		},
		RunDetails: RunDetails{
			Builder:    Builder{ID: builderID, Version: builderVer},
			Metadata:   Metadata{InvocationID: invocationID(), StartedOn: in.StartedOn, FinishedOn: time.Now().UTC()},
			Byproducts: byproducts,
		},
	}
}

func identifyBuilder(tool, toolVersion string) (string, map[string]string) {
	if tool == "" {
		tool = "tool"
	}
	ver := map[string]string{tool: toolVersion, "go": runtime.Version(), "go-arch": runtime.GOARCH, "go-os": runtime.GOOS}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return fmt.Sprintf("%s/%s/actions/runs/%s", envOr("GITHUB_SERVER_URL", "https://github.com"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID")), ver
	}
	host, _ := os.Hostname()
	return fmt.Sprintf("local://%s@%s", envOr("USER", envOr("USERNAME", "unknown")), host), ver
}

func internalParams() map[string]any {
	out := map[string]any{}
	for _, k := range []string{"GITHUB_ACTIONS", "GITHUB_WORKFLOW", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA", "GITHUB_ACTOR", "RUNNER_OS", "CI"} {
		if v := os.Getenv(k); v != "" {
			out[k] = v
		}
	}
	return out
}

func invocationID() string {
	v := os.Getenv("GITHUB_RUN_ID")
	if v == "" {
		return ""
	}
	if a := os.Getenv("GITHUB_RUN_ATTEMPT"); a != "" {
		return v + "-" + a
	}
	return v
}

func detectGit() *ResourceDescr {
	remote, err := gitCmd("config", "--get", "remote.origin.url")
	if err != nil || remote == "" {
		return nil
	}
	sha, err := gitCmd("rev-parse", "HEAD")
	if err != nil || sha == "" {
		return nil
	}
	return &ResourceDescr{
		Name:   "source",
		URI:    "git+" + strings.TrimSuffix(stripUserinfo(remote), ".git") + "@" + sha,
		Digest: map[string]string{"gitCommit": sha},
	}
}

// stripUserinfo drops user:token@ from URL-shaped remotes so a CI checkout
// token never lands in a public attestation.
func stripUserinfo(remote string) string {
	u, err := url.Parse(remote)
	if err != nil || u.Scheme == "" || u.User == nil {
		return remote
	}
	u.User = nil
	return u.String()
}

func gitCmd(args ...string) (string, error) {
	out, err := exec.Command("git", args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func digestMap(prefixed string) map[string]string {
	if alg, hex, ok := strings.Cut(prefixed, ":"); ok {
		return map[string]string{alg: hex}
	}
	return map[string]string{"sha256": prefixed}
}
