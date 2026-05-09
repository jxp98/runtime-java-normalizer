package normalizer

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"runtime-java-normalizer/internal/api"
)

const (
	manifestEntryPath     = "META-INF/MANIFEST.MF"
	pomPropertiesSuffix   = "/pom.properties"
	nestedDiscoverySource = "nested_archive"
	defaultSchemaVersion  = "1.0"
)

var artifactVersionPattern = regexp.MustCompile(`^(.+)-([0-9][A-Za-z0-9._-]*)$`)

type archiveMetadata struct {
	groupID              string
	artifactID           string
	version              string
	purl                 string
	sha1                 string
	evidenceSource       string
	confidence           string
	packageType          string
	artifactFromManifest bool
	versionFromManifest  bool
	groupFromManifest    bool
	artifactFromFilename bool
	versionFromFilename  bool
}

type Service struct{}

func New() *Service {
	return &Service{}
}

func (s *Service) Normalize(request api.NormalizeRequest) api.NormalizeResponse {
	response := api.NormalizeResponse{
		SchemaVersion: valueOrDefault(request.SchemaVersion, defaultSchemaVersion),
		GeneratedAt:   api.NowISO8601(),
		Components:    make([]api.Component, 0),
	}

	for _, candidate := range request.Candidates {
		response.Components = append(response.Components, normalizeCandidate(candidate)...)
	}

	return response
}

func normalizeCandidate(candidate api.Candidate) []api.Component {
	runtimePath := filepath.Clean(strings.TrimSpace(candidate.RuntimePath))
	if runtimePath == "" {
		return nil
	}

	metadata := resolveArchiveMetadataFromFile(runtimePath, runtimePath)
	components := []api.Component{buildComponent(runtimePath, "", "", candidate.DiscoverySource, candidate.IsDirectRuntimeTarget, false, metadata)}

	if !candidate.IsDirectRuntimeTarget {
		return components
	}

	reader, err := zip.OpenReader(runtimePath)
	if err != nil {
		return components
	}
	defer reader.Close()

	nestedSource := mergeDiscoverySources(candidate.DiscoverySource, nestedDiscoverySource)
	for _, file := range reader.File {
		if !isArchivePath(file.Name) || !strings.Contains(file.Name, "/") {
			continue
		}

		content, err := readZipFile(file)
		if err != nil {
			fallback := resolveArchiveMetadataFromBytes(nil, file.Name)
			components = append(components, buildComponent(runtimePath, runtimePath, file.Name, nestedSource, false, true, fallback))
			continue
		}

		nestedMetadata := resolveArchiveMetadataFromBytes(content, file.Name)
		components = append(components, buildComponent(runtimePath, runtimePath, file.Name, nestedSource, false, true, nestedMetadata))
	}

	return components
}

func buildComponent(runtimePath, archivePath, pathInArchive, discoverySource string, isDirectRuntimeTarget, isNested bool, metadata archiveMetadata) api.Component {
	return api.Component{
		RuntimePath:           runtimePath,
		ArchivePath:           archivePath,
		PathInArchive:         pathInArchive,
		PackageType:           metadata.packageType,
		GroupID:               metadata.groupID,
		ArtifactID:            metadata.artifactID,
		Version:               metadata.version,
		PURL:                  metadata.purl,
		SHA1:                  metadata.sha1,
		EvidenceSource:        metadata.evidenceSource,
		Confidence:            metadata.confidence,
		DiscoverySource:       discoverySource,
		IsDirectRuntimeTarget: isDirectRuntimeTarget,
		IsNested:              isNested,
		DiscoveredAt:          api.NowISO8601(),
	}
}

func resolveArchiveMetadataFromFile(archivePath, componentPathHint string) archiveMetadata {
	metadata := archiveMetadata{sha1: computeFileSHA1(archivePath)}
	reader, err := zip.OpenReader(archivePath)
	if err == nil {
		defer reader.Close()
		fillMetadataFromZip(&metadata, &reader.Reader, componentPathHint)
	}
	completeMetadata(&metadata, componentPathHint)
	return metadata
}

func resolveArchiveMetadataFromBytes(content []byte, componentPathHint string) archiveMetadata {
	metadata := archiveMetadata{}
	if len(content) > 0 {
		metadata.sha1 = computeBytesSHA1(content)
		reader, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
		if err == nil {
			fillMetadataFromZip(&metadata, reader, componentPathHint)
		}
	}
	completeMetadata(&metadata, componentPathHint)
	return metadata
}

func fillMetadataFromZip(metadata *archiveMetadata, reader *zip.Reader, componentPathHint string) {
	if metadata == nil || reader == nil {
		return
	}

	if pomFile := findPomPropertiesFile(reader); pomFile != nil {
		properties := parseProperties(readZipFileString(pomFile))
		metadata.groupID = valueOrDefault(metadata.groupID, properties["groupId"])
		metadata.artifactID = valueOrDefault(metadata.artifactID, properties["artifactId"])
		metadata.version = valueOrDefault(metadata.version, properties["version"])
		if metadata.groupID != "" || metadata.artifactID != "" || metadata.version != "" {
			metadata.evidenceSource = "pom.properties"
			metadata.confidence = "high"
		}
	}

	if manifestFile := findEntry(reader, manifestEntryPath); manifestFile != nil {
		manifest := parseManifest(readZipFileString(manifestFile))
		manifestArtifact := chooseManifestArtifact(manifest, componentPathHint)
		manifestVersion := firstNonEmpty(
			sanitizeManifestValue(manifest["Implementation-Version"]),
			sanitizeManifestValue(manifest["Bundle-Version"]),
			sanitizeManifestValue(manifest["Specification-Version"]),
		)
		manifestGroup := firstCoordinateLike(
			sanitizeManifestValue(manifest["Implementation-Vendor-Id"]),
			extractGroupFromBundleSymbolicName(manifest["Bundle-SymbolicName"]),
		)

		if metadata.artifactID == "" && manifestArtifact != "" {
			metadata.artifactID = manifestArtifact
			metadata.artifactFromManifest = true
		}
		if metadata.version == "" && manifestVersion != "" {
			metadata.version = manifestVersion
			metadata.versionFromManifest = true
		}
		if metadata.groupID == "" && manifestGroup != "" {
			metadata.groupID = manifestGroup
			metadata.groupFromManifest = true
		}
	}
}

func completeMetadata(metadata *archiveMetadata, componentPathHint string) {
	if metadata == nil {
		return
	}

	artifactID, version := inferArtifactAndVersion(componentPathHint)
	if metadata.artifactID == "" && artifactID != "" {
		metadata.artifactID = artifactID
		metadata.artifactFromFilename = true
	}
	if metadata.version == "" && version != "" {
		metadata.version = version
		metadata.versionFromFilename = true
	}
	if metadata.evidenceSource == "" {
		if metadata.artifactFromManifest || metadata.versionFromManifest || metadata.groupFromManifest {
			if metadata.artifactFromFilename || metadata.versionFromFilename {
				metadata.evidenceSource = "manifest+filename"
			} else {
				metadata.evidenceSource = "manifest"
			}
			metadata.confidence = "medium"
		} else {
			metadata.evidenceSource = "filename"
			metadata.confidence = "low"
		}
	}
	metadata.purl = buildMavenPURL(metadata.groupID, metadata.artifactID, metadata.version)
	if metadata.purl == "" {
		metadata.packageType = "jar"
	} else {
		metadata.packageType = "maven"
	}
}

func findPomPropertiesFile(reader *zip.Reader) *zip.File {
	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "META-INF/maven/") && strings.HasSuffix(file.Name, pomPropertiesSuffix) {
			return file
		}
	}
	return nil
}

func findEntry(reader *zip.Reader, entryName string) *zip.File {
	for _, file := range reader.File {
		if file.Name == entryName {
			return file
		}
	}
	return nil
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

func readZipFileString(file *zip.File) string {
	content, err := readZipFile(file)
	if err != nil {
		return ""
	}
	return string(content)
}

func parseProperties(content string) map[string]string {
	result := make(map[string]string)
	for _, line := range splitLines(content) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		separator := strings.IndexRune(line, '=')
		if separator < 0 {
			continue
		}
		result[strings.TrimSpace(line[:separator])] = strings.TrimSpace(line[separator+1:])
	}
	return result
}

func parseManifest(content string) map[string]string {
	result := make(map[string]string)
	var unfolded []string
	current := ""
	for _, line := range splitLines(content) {
		if strings.HasPrefix(line, " ") {
			current += strings.TrimPrefix(line, " ")
			continue
		}
		if current != "" {
			unfolded = append(unfolded, current)
		}
		current = line
	}
	if current != "" {
		unfolded = append(unfolded, current)
	}
	for _, line := range unfolded {
		separator := strings.IndexRune(line, ':')
		if separator < 0 {
			continue
		}
		result[strings.TrimSpace(line[:separator])] = strings.TrimSpace(line[separator+1:])
	}
	return result
}

func splitLines(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	if content == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(content, "\n"), "\n")
}

func inferArtifactAndVersion(path string) (string, string) {
	filename := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	matches := artifactVersionPattern.FindStringSubmatch(filename)
	if len(matches) == 3 {
		return matches[1], matches[2]
	}
	return filename, ""
}

func buildMavenPURL(groupID, artifactID, version string) string {
	if groupID == "" || artifactID == "" || version == "" {
		return ""
	}
	return fmt.Sprintf("pkg:maven/%s/%s@%s", groupID, artifactID, version)
}

func computeFileSHA1(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	hasher := sha1.New()
	if _, err = io.Copy(hasher, file); err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func computeBytesSHA1(content []byte) string {
	hasher := sha1.Sum(content)
	return hex.EncodeToString(hasher[:])
}

func isArchivePath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".jar" || ext == ".war" || ext == ".ear"
}

func mergeDiscoverySources(current, next string) string {
	seen := make(map[string]struct{})
	for _, source := range strings.Split(current, ",") {
		source = strings.TrimSpace(source)
		if source != "" {
			seen[source] = struct{}{}
		}
	}
	if next != "" {
		seen[next] = struct{}{}
	}
	merged := make([]string, 0, len(seen))
	for source := range seen {
		merged = append(merged, source)
	}
	sort.Strings(merged)
	return strings.Join(merged, ",")
}

func sanitizeManifestValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(trimmed, "%") {
		return ""
	}
	return trimmed
}

func looksLikeCoordinateValue(value string) bool {
	trimmed := sanitizeManifestValue(value)
	if trimmed == "" || strings.ContainsAny(trimmed, " \t/\\:@") {
		return false
	}
	for _, ch := range trimmed {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			continue
		}
		if ch != '.' && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}

func normalizeArtifactKey(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(trimmed))
	lastDash := false
	for _, ch := range trimmed {
		switch {
		case (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'):
			builder.WriteRune(ch)
			lastDash = false
		case ch == '.' || ch == '_' || ch == '-':
			if !lastDash {
				builder.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(builder.String(), "-")
}

func sameArtifactIdentity(left, right string) bool {
	leftKey := normalizeArtifactKey(left)
	rightKey := normalizeArtifactKey(right)
	return leftKey != "" && leftKey == rightKey
}

func firstCoordinateLike(values ...string) string {
	for _, value := range values {
		if looksLikeCoordinateValue(value) {
			return sanitizeManifestValue(value)
		}
	}
	return ""
}

func chooseManifestArtifact(manifest map[string]string, componentPathHint string) string {
	manifestArtifact := firstCoordinateLike(
		manifest["Implementation-Title"],
		manifest["Bundle-Name"],
		manifest["Specification-Title"],
	)
	if manifestArtifact == "" {
		return ""
	}
	filenameArtifact, _ := inferArtifactAndVersion(componentPathHint)
	if filenameArtifact == "" {
		return manifestArtifact
	}
	if sameArtifactIdentity(manifestArtifact, filenameArtifact) {
		return filenameArtifact
	}
	return ""
}

func extractArtifactFromBundleSymbolicName(value string) string {
	if value == "" {
		return ""
	}
	value = strings.Split(value, ";")[0]
	lastDot := strings.LastIndex(value, ".")
	if lastDot < 0 {
		return value
	}
	return value[lastDot+1:]
}

func extractGroupFromBundleSymbolicName(value string) string {
	value = sanitizeManifestValue(value)
	if value == "" {
		return ""
	}
	value = strings.Split(value, ";")[0]
	lastDot := strings.LastIndex(value, ".")
	if lastDot < 0 {
		return ""
	}
	return value[:lastDot]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func valueOrDefault(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return strings.TrimSpace(value)
}
