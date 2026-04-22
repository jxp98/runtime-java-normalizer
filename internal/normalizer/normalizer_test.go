package normalizer

import (
	"path/filepath"
	"testing"

	"runtime-java-normalizer/internal/api"
)

func testJarPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Clean(filepath.Join("..", "..", "..", "wazuh", "src", "wazuh_modules", "syscollector", "tests", "sysCollectorImp", "data", name))
}

func TestNormalizeUsesPomPropertiesWhenAvailable(t *testing.T) {
	response := New().Normalize(api.NormalizeRequest{
		Candidates: []api.Candidate{{
			RuntimePath:     testJarPath(t, "log4j-core-2.17.2.jar"),
			DiscoverySource: "classpath",
		}},
	})

	if len(response.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(response.Components))
	}
	component := response.Components[0]
	if component.GroupID != "org.apache.logging.log4j" || component.ArtifactID != "log4j-core" || component.Version != "2.17.2" {
		t.Fatalf("unexpected component identity: %#v", component)
	}
	if component.PURL != "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.2" {
		t.Fatalf("unexpected purl: %s", component.PURL)
	}
	if component.SHA1 != "52fdcc7402c7b5c82f32a17b11f4d5874b560e38" {
		t.Fatalf("unexpected sha1: %s", component.SHA1)
	}
	if component.EvidenceSource != "pom.properties" || component.Confidence != "high" {
		t.Fatalf("unexpected evidence: %#v", component)
	}
}

func TestNormalizeFallsBackToManifest(t *testing.T) {
	response := New().Normalize(api.NormalizeRequest{
		Candidates: []api.Candidate{{
			RuntimePath:           testJarPath(t, "custom-app.jar"),
			DiscoverySource:       "jar",
			IsDirectRuntimeTarget: true,
		}},
	})

	if len(response.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(response.Components))
	}
	component := response.Components[0]
	if component.ArtifactID != "custom-app" || component.Version != "1.4.7" {
		t.Fatalf("unexpected component identity: %#v", component)
	}
	if component.SHA1 != "c82fe3eaf49fe05c30d93f1f7a0ed4aa1acbe207" {
		t.Fatalf("unexpected sha1: %s", component.SHA1)
	}
	if component.EvidenceSource != "manifest" || component.Confidence != "medium" {
		t.Fatalf("unexpected evidence: %#v", component)
	}
}

func TestNormalizeCollectsNestedLibraries(t *testing.T) {
	response := New().Normalize(api.NormalizeRequest{
		Candidates: []api.Candidate{{
			RuntimePath:           testJarPath(t, "demo-app-1.0.0.jar"),
			DiscoverySource:       "jar",
			IsDirectRuntimeTarget: true,
		}},
	})

	if len(response.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(response.Components))
	}
	if response.Components[0].ArtifactID != "demo-app" || response.Components[0].Version != "1.0.0" {
		t.Fatalf("unexpected root component: %#v", response.Components[0])
	}
	if response.Components[1].ArchivePath != response.Components[0].RuntimePath || response.Components[1].PathInArchive != "BOOT-INF/lib/log4j-core-2.14.1.jar" {
		t.Fatalf("unexpected nested log4j component: %#v", response.Components[1])
	}
	if response.Components[1].GroupID != "org.apache.logging.log4j" || response.Components[1].SHA1 != "c5a52d75b03c4d197b35446d5cd0e7f85a8e986b" {
		t.Fatalf("unexpected nested log4j component: %#v", response.Components[1])
	}
	if response.Components[2].GroupID != "org.springframework" || response.Components[2].PathInArchive != "BOOT-INF/lib/spring-core-5.3.17.jar" {
		t.Fatalf("unexpected nested spring component: %#v", response.Components[2])
	}
	if response.Components[2].SHA1 != "50a151700885104778a7712d2488efeb77f9908b" {
		t.Fatalf("unexpected nested spring sha1: %#v", response.Components[2])
	}
}
