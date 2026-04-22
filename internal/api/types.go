package api

import "time"

type NormalizeRequest struct {
	SchemaVersion string      `json:"schema_version"`
	Candidates    []Candidate `json:"candidates"`
}

type Candidate struct {
	RuntimePath           string `json:"runtime_path"`
	DiscoverySource       string `json:"discovery_source,omitempty"`
	IsDirectRuntimeTarget bool   `json:"is_direct_runtime_target,omitempty"`
}

type NormalizeResponse struct {
	SchemaVersion string      `json:"schema_version"`
	GeneratedAt   string      `json:"generated_at"`
	Components    []Component `json:"components"`
}

type Component struct {
	RuntimePath           string `json:"runtime_path,omitempty"`
	ArchivePath           string `json:"archive_path,omitempty"`
	PathInArchive         string `json:"path_in_archive,omitempty"`
	PackageType           string `json:"package_type,omitempty"`
	GroupID               string `json:"group_id,omitempty"`
	ArtifactID            string `json:"artifact_id,omitempty"`
	Version               string `json:"version_,omitempty"`
	PURL                  string `json:"purl,omitempty"`
	SHA1                  string `json:"sha1,omitempty"`
	EvidenceSource        string `json:"evidence_source,omitempty"`
	Confidence            string `json:"confidence,omitempty"`
	DiscoverySource       string `json:"discovery_source,omitempty"`
	IsDirectRuntimeTarget bool   `json:"is_direct_runtime_target,omitempty"`
	IsNested              bool   `json:"is_nested,omitempty"`
	DiscoveredAt          string `json:"discovered_at,omitempty"`
}

func NowISO8601() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
