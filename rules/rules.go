// Package rules gets OpenWeir's routing template, and the rule sets it uses, from the rules
// branch of github.com/openweir/subconv, which a workflow regenerates daily.
//
// The branch is served by several CDNs under the same paths. A [Client] asks all of them for
// the manifest at once, takes the version that independent operators agree on, ranks the hosts
// serving it by speed, and checks every file it downloads against the manifest. The caller
// supplies the *http.Client (and with it routing, proxies and address policy) and, optionally, a
// [Cache] that keeps the last good manifest and files for when no host answers.
//
// The template names the branch's base URL as [Placeholder]; [Fill] puts the chosen host in.
package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Placeholder stands for the base URL of the branch in the template's rule provider URLs.
const Placeholder = "{rules}"

// Where the manifest and the template lie in the branch.
const (
	ManifestPath = "manifest.json"
	TemplatePath = "template.yaml"
)

// A Host serves the branch.
type Host struct {
	// Base is the URL of the branch's root, without a trailing slash.
	Base string
	// Operator names who runs the host. Hosts of one operator share a cache and an origin, so
	// they count as one source when hosts must agree on a manifest.
	Operator string
	// Hops counts the caches between the host and the branch itself: 0 for GitHub, 1 for
	// jsDelivr, 2 for a mirror of jsDelivr. When operators disagree, the fewest hops win.
	Hops int
}

var defaultHosts = []Host{
	{Base: "https://cdn.jsdmirror.com/gh/openweir/subconv@rules", Operator: "jsdmirror", Hops: 2},
	{Base: "https://fastly.jsdelivr.net/gh/openweir/subconv@rules", Operator: "jsdelivr", Hops: 1},
	{Base: "https://testingcf.jsdelivr.net/gh/openweir/subconv@rules", Operator: "jsdelivr", Hops: 1},
	{Base: "https://gcore.jsdelivr.net/gh/openweir/subconv@rules", Operator: "jsdelivr", Hops: 1},
	{Base: "https://cdn.jsdelivr.net/gh/openweir/subconv@rules", Operator: "jsdelivr", Hops: 1},
	{Base: "https://raw.githubusercontent.com/openweir/subconv/rules", Operator: "github", Hops: 0},
}

// DefaultHosts returns the hosts of the branch, in the order to try them before any was timed:
// the mirror reachable in mainland China first, then jsDelivr's hostnames, then GitHub.
func DefaultHosts() []Host { return slices.Clone(defaultHosts) }

// Manifest lists every file on the branch.
type Manifest struct {
	// Version grows with every publish (the build's Unix time). Clients never go back to a
	// lower version than one they have seen, which a stale mirror would otherwise serve.
	Version int64 `json:"version"`
	// Generated is when the branch was built, in RFC 3339.
	Generated string   `json:"generated"`
	Files     []File   `json:"files"`
	Sources   []Source `json:"sources,omitempty"`
}

// File describes one file of the branch.
type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// Updated is the date (YYYY-MM-DD) the content last changed.
	Updated string `json:"updated"`
	// Kind is template, rule-set, license or notice.
	Kind string `json:"kind"`
	// Behavior, Format and Entries describe a rule set as mihomo reads it.
	Behavior string `json:"behavior,omitempty"`
	Format   string `json:"format,omitempty"`
	Entries  int    `json:"entries,omitempty"`
	// Source is the upstream URL the content comes from, License its SPDX identifier (or a
	// LicenseRef-), and Retrieved the date (YYYY-MM-DD) it was downloaded.
	Source    string `json:"source,omitempty"`
	License   string `json:"license,omitempty"`
	Retrieved string `json:"retrieved,omitempty"`
}

// Source describes where a part of the branch comes from.
type Source struct {
	Name    string `json:"name"`
	Home    string `json:"home"`
	Commit  string `json:"commit,omitempty"`
	License string `json:"license"`
}

// Errors of the package. Errors about one host are a *HostError wrapping one of these, or the
// network's error.
var (
	ErrInvalidManifest = errors.New("rules: invalid manifest")
	ErrNotListed       = errors.New("rules: file not in the manifest")
	ErrTooLarge        = errors.New("rules: response larger than allowed")
	ErrDigest          = errors.New("rules: content does not match the manifest")
	ErrRollback        = errors.New("rules: manifest older than one already seen")
	ErrInsecure        = errors.New("rules: a single source must be served over HTTPS")
	ErrNoManifest      = errors.New("rules: no host served a usable manifest")
	ErrInvalidBase     = errors.New("rules: invalid base URL")
)

// HostError is a failure of one host.
type HostError struct {
	Host string
	Err  error
}

func (e *HostError) Error() string { return e.Host + ": " + e.Err.Error() }
func (e *HostError) Unwrap() error { return e.Err }

// ParseManifest decodes a manifest and checks that it is complete: a version, safe unique paths,
// SHA-256 digests, and the template.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidManifest, err)
	}
	if m.Version <= 0 {
		return nil, fmt.Errorf("%w: no version", ErrInvalidManifest)
	}
	seen := make(map[string]bool, len(m.Files))
	for _, f := range m.Files {
		if !ValidPath(f.Path) || seen[f.Path] {
			return nil, fmt.Errorf("%w: path %q", ErrInvalidManifest, f.Path)
		}
		seen[f.Path] = true
		if f.Size < 0 || len(f.SHA256) != 64 || !isHex(f.SHA256) {
			return nil, fmt.Errorf("%w: %s: size or digest", ErrInvalidManifest, f.Path)
		}
	}
	if !seen[TemplatePath] {
		return nil, fmt.Errorf("%w: no %s", ErrInvalidManifest, TemplatePath)
	}
	return &m, nil
}

// File returns the entry of a path.
func (m *Manifest) File(path string) (File, bool) {
	for _, f := range m.Files {
		if f.Path == path {
			return f, true
		}
	}
	return File{}, false
}

// Matches reports whether data is the file's content.
func (f File) Matches(data []byte) bool {
	return int64(len(data)) == f.Size && digest(data) == f.SHA256
}

// ValidPath reports whether p is a path the branch may hold: relative, slash-separated, without
// dot segments, of letters, digits, '.', '_' and '-'. Such paths are also usable as cache keys
// and file names.
func ValidPath(p string) bool {
	if p == "" || len(p) > 200 {
		return false
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for _, r := range seg {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Fill replaces [Placeholder] in the template with base, the URL of the branch on the chosen host.
// base must be an http(s) URL that needs no quoting in YAML.
func Fill(template []byte, base string) ([]byte, error) {
	base = strings.TrimSuffix(base, "/")
	if err := checkBase(base); err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(template, []byte(Placeholder), []byte(base)), nil
}

func checkBase(base string) error {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: %q", ErrInvalidBase, base)
	}
	for _, r := range base {
		if r <= ' ' || r == 0x7f || strings.ContainsRune(`"'\#{}`, r) {
			return fmt.Errorf("%w: %q", ErrInvalidBase, base)
		}
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}
