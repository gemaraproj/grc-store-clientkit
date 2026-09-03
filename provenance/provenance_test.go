// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuild_BasicShape(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("USER", "testuser")
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	p := Build(Input{
		Tool: "pvtr", ToolVersion: "1.2.3", StartedOn: now,
		ArtifactType: "EvaluationLog", ArtifactID: "my-log", ArtifactName: "log.yaml", ArtifactDigest: "sha256:abc123",
		SourceFiles: map[string]string{"b.yaml": "sha256:bbb", "a.yaml": "sha256:aaa"},
		Registry:    "registry.example", Repository: "team/my-log", Tag: "1.0.0-run1",
		Evaluator: &Evaluator{Coordinate: "acme/scanner", IndexDigest: "sha256:idx", TargetID: "tgt", TargetVersion: "1.0.0", RunID: "run1"},
	})

	if p.BuildDefinition.BuildType != BuildType || p.RunDetails.Metadata.StartedOn != now || p.RunDetails.Metadata.FinishedOn.IsZero() {
		t.Errorf("build type / timestamps wrong: %+v", p)
	}
	if p.RunDetails.Builder.Version["pvtr"] != "1.2.3" || !strings.HasPrefix(p.RunDetails.Builder.ID, "local://testuser@") {
		t.Errorf("builder = %+v", p.RunDetails.Builder)
	}
	ext := p.BuildDefinition.ExternalParameters
	if !reflect.DeepEqual(ext["artifact"], map[string]string{"type": "EvaluationLog", "id": "my-log"}) ||
		!reflect.DeepEqual(ext["target"], map[string]string{"registry": "registry.example", "repository": "team/my-log", "tag": "1.0.0-run1"}) ||
		!reflect.DeepEqual(ext["evaluator"], map[string]string{"coordinate": "acme/scanner", "target_id": "tgt", "target_version": "1.0.0", "run_id": "run1"}) {
		t.Errorf("externalParameters = %+v", ext)
	}
	deps := p.BuildDefinition.ResolvedDependencies
	if len(deps) < 3 || deps[0].Name != "a.yaml" || deps[1].Name != "b.yaml" || deps[0].Digest["sha256"] != "aaa" {
		t.Errorf("source files must be first and sorted: %+v", deps)
	}
	last := deps[len(deps)-1]
	if last.Name != "evaluator" || last.URI != "oci://registry.example/acme/scanner" || last.Digest["sha256"] != "idx" {
		t.Errorf("evaluator dependency = %+v", last)
	}
	if len(p.RunDetails.Byproducts) != 1 || p.RunDetails.Byproducts[0].Digest["sha256"] != "abc123" {
		t.Errorf("byproducts = %+v", p.RunDetails.Byproducts)
	}
}

func TestBuild_GitHubActions(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "acme/repo")
	t.Setenv("GITHUB_RUN_ID", "42")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	p := Build(Input{StartedOn: time.Now()})
	if p.RunDetails.Builder.ID != "https://github.com/acme/repo/actions/runs/42" || p.RunDetails.Metadata.InvocationID != "42-1" {
		t.Errorf("builder id %q, invocation %q", p.RunDetails.Builder.ID, p.RunDetails.Metadata.InvocationID)
	}
	if p.BuildDefinition.InternalParameters["GITHUB_RUN_ID"] != "42" {
		t.Errorf("internalParameters = %+v", p.BuildDefinition.InternalParameters)
	}
}

func TestBuild_SerializesAsJSON(t *testing.T) {
	b, err := json.Marshal(Build(Input{StartedOn: time.Now(), SourceFiles: map[string]string{"x": "sha256:1"}}))
	if err != nil || !strings.Contains(string(b), `"buildType"`) || !strings.Contains(string(b), `"resolvedDependencies"`) {
		t.Errorf("err=%v json=%s", err, b)
	}
}

func TestStripUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"https://user:tok3n@github.com/org/repo.git":         "https://github.com/org/repo.git",
		"https://x-access-token:ghs_abc@github.com/org/repo": "https://github.com/org/repo",
		"https://github.com/org/repo.git":                    "https://github.com/org/repo.git",
		"git@github.com:org/repo.git":                        "git@github.com:org/repo.git",
		"ssh://git@github.com/org/repo.git":                  "ssh://github.com/org/repo.git",
	} {
		if got := stripUserinfo(in); got != want {
			t.Errorf("stripUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}
