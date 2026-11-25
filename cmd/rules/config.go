package main

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/openweir/subconv/rules"
)

// config is what config.yaml holds: where the layout and rule sets come from, under which
// licenses, and the groups the template routes to.
type config struct {
	// MaxSize bounds a downloaded file, in bytes.
	MaxSize int64 `yaml:"max-size"`
	// MaxShrink fails the build when a rule set loses more than this share of its entries since
	// the previous build: an upstream serving a truncated file must not empty the branch.
	MaxShrink float64 `yaml:"max-shrink"`
	// SplitMin is the number of domains and IP ranges from which a classical rule set is split
	// into parts; a smaller set stays whole.
	SplitMin int `yaml:"split-min"`
	// Interval is the rule providers' refresh interval in the template, in seconds.
	Interval int `yaml:"interval"`
	// ProviderPath is where mihomo keeps the rule sets, relative to its home directory.
	ProviderPath string `yaml:"provider-path"`
	// Notice heads NOTICE.md; Readme is the branch's README.md.
	Notice   string     `yaml:"notice"`
	Readme   string     `yaml:"readme"`
	Sources  []*source  `yaml:"sources"`
	Licenses []*license `yaml:"licenses"`
	Template *tmpl      `yaml:"template"`
}

// source is an upstream of layouts and rule sets.
type source struct {
	Name string `yaml:"name"`
	Home string `yaml:"home"`
	// Refs are the URL prefixes that layouts use for the source's files.
	Refs []string `yaml:"refs"`
	// Fetch is the URL prefix to download them from; {commit} stands for the commit Repository
	// and Branch name.
	Fetch string `yaml:"fetch"`
	// Archive, if set, is a tar.gz of the whole source to read the files from instead, in one
	// download; {commit} again stands for the commit. Fetch then only names the files' origin in
	// the manifest.
	Archive string `yaml:"archive"`
	// Repository, if set, is the source's git repository, and Branch the branch whose head
	// commit the build downloads, read as git ls-remote reads it, so one build reads one state
	// of the source.
	Repository string `yaml:"repository"`
	Branch     string `yaml:"branch"`
	// Output is the source's directory under providers/; Strip is the path prefix of its files
	// that output paths leave out.
	Output string `yaml:"output"`
	Strip  string `yaml:"strip"`
	// License is the SPDX identifier (or LicenseRef-) of the source's files. With
	// LicenseHeader, a file's own "# License:" comment overrides it.
	License       string `yaml:"license"`
	LicenseHeader bool   `yaml:"license-header"`
	// Notice is the source's attribution in NOTICE.md.
	Notice string `yaml:"notice"`

	commit string
	files  map[string][]byte // the archive's
}

type license struct {
	ID string `yaml:"id"`
	// Names are how files' "# License:" comments spell it.
	Names []string `yaml:"names"`
	// Text is the URL of the license text, shipped in LICENSES/; URI is where the license
	// lies, for licenses that ask only for a reference.
	Text string `yaml:"text"`
	URI  string `yaml:"uri"`
}

type tmpl struct {
	// Layout is the URL of the Clash rules and rule providers to mirror, as a source refers
	// to it.
	Layout      string `yaml:"layout"`
	Description string `yaml:"description"`
	// Policies sends the layout's rules for one policy to a group of the template: one named
	// otherwise, or one that takes several of the layout's groups.
	Policies map[string]string `yaml:"policies"`
	// Rules are OpenWeir's own rules: the template starts with them, ahead of the layout's.
	// Their policies go through Policies like the layout's.
	Rules []string `yaml:"rules"`
	// Additions are entries OpenWeir adds to the layout's rule sets, by the name the layout
	// gives a set; they are merged into its content before it is split.
	Additions map[string][]string `yaml:"additions"`
	Groups    []rules.Group       `yaml:"groups"`
}

func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(data)
}

func parseConfig(data []byte) (*config, error) {
	var cfg config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if cfg.MaxSize <= 0 || cfg.Interval <= 0 || cfg.SplitMin <= 0 || cfg.MaxShrink <= 0 || cfg.MaxShrink >= 1 {
		return nil, fmt.Errorf("config: max-size, interval, split-min and max-shrink (0 to 1) are required")
	}
	if !rules.ValidPath(strings.TrimPrefix(cfg.ProviderPath, "./")) || !strings.HasPrefix(cfg.ProviderPath, "./") {
		return nil, fmt.Errorf("config: provider-path %q", cfg.ProviderPath)
	}
	outputs := map[string]bool{}
	for _, s := range cfg.Sources {
		if s.Name == "" || s.Fetch == "" || len(s.Refs) == 0 || !rules.ValidPath(s.Output) || outputs[s.Output] || s.License == "" {
			return nil, fmt.Errorf("config: source %q is incomplete", s.Name)
		}
		outputs[s.Output] = true
		pinned := s.Repository != ""
		if pinned != (s.Branch != "") || pinned != strings.Contains(s.Fetch+s.Archive, "{commit}") || pinned && !rules.ValidPath(s.Branch) {
			return nil, fmt.Errorf("config: source %s: {commit}, repository and branch go together", s.Name)
		}
		if cfg.license(s.License) == nil {
			return nil, fmt.Errorf("config: source %s: unknown license %s", s.Name, s.License)
		}
	}
	t := cfg.Template
	if t == nil || t.Layout == "" || len(t.Groups) == 0 {
		return nil, fmt.Errorf("config: the template needs a layout and groups")
	}
	for _, r := range t.Rules {
		if f := rules.SplitRule(r); len(f) < 3 || strings.EqualFold(f[0], "RULE-SET") || strings.EqualFold(f[0], "MATCH") {
			return nil, fmt.Errorf("config: rule %q: rule sets and MATCH come from the layout, and a rule needs a policy", r)
		}
	}
	for set, entries := range t.Additions {
		for _, e := range entries {
			// Entries name no policy: the set's rules in the layout give it.
			f := rules.SplitRule(e)
			policy := len(f) > 3 || len(f) == 3 && !strings.EqualFold(f[2], "no-resolve")
			if _, _, ok := splitClassical(e); !ok || policy {
				return nil, fmt.Errorf("config: addition %q to %s is not a rule a rule set holds", e, set)
			}
		}
	}
	for i := range t.Groups {
		g := &t.Groups[i]
		for _, f := range []*string{&g.Filter, &g.ExcludeFilter} {
			*f = strings.ReplaceAll(*f, rules.InfoToken, rules.InfoFilter)
		}
	}
	return &cfg, nil
}

// sourceOf returns the source a URL refers to, and the file's path within it, unescaped.
func (cfg *config) sourceOf(u string) (*source, string, bool) {
	for _, s := range cfg.Sources {
		for _, ref := range s.Refs {
			if rest, ok := strings.CutPrefix(u, ref); ok && rest != "" {
				path, err := url.PathUnescape(rest)
				if err != nil || strings.Contains(path, "..") {
					return nil, "", false
				}
				return s, path, true
			}
		}
	}
	return nil, "", false
}

func (cfg *config) license(id string) *license {
	for _, l := range cfg.Licenses {
		if l.ID == id {
			return l
		}
	}
	return nil
}

// licenseNamed returns the license a file's "# License:" comment names.
func (cfg *config) licenseNamed(name string) *license {
	for _, l := range cfg.Licenses {
		for _, n := range append([]string{l.ID}, l.Names...) {
			if strings.EqualFold(n, name) {
				return l
			}
		}
	}
	return nil
}
