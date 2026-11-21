package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/rules"
)

// converter compiles a text rule set into mihomo's binary format.
type converter func(ctx context.Context, behavior, src, dst string) error

// builder writes the branch into an empty directory.
type builder struct {
	cfg     *config
	fetch   *fetcher
	convert converter // nil writes text rule sets only
	out     string
	now     time.Time
	prev    *rules.Manifest
	log     io.Writer

	sets  map[string]*ruleSet // by the URL layouts name them by
	bases map[string]string   // output base → that URL
	files map[string]*rules.File
}

type layoutDoc struct {
	Rules     []string                  `yaml:"rules"`
	Providers map[string]layoutProvider `yaml:"rule-providers"`
}

type layoutProvider struct {
	Type     string `yaml:"type"`
	Behavior string `yaml:"behavior"`
	Format   string `yaml:"format"`
	URL      string `yaml:"url"`
}

// templateStats sums up what a template makes mihomo load.
type templateStats struct {
	providers, entries int
	bytes              int64
}

// build writes the branch and returns the paths that differ from the previous manifest, the
// manifest last; none if nothing changed.
func (b *builder) build(ctx context.Context) ([]string, error) {
	b.sets, b.bases, b.files = map[string]*ruleSet{}, map[string]string{}, map[string]*rules.File{}
	if entries, err := os.ReadDir(b.out); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty", b.out)
	}
	for _, s := range b.cfg.Sources {
		if err := b.fetch.resolveCommit(ctx, s); err != nil {
			return nil, err
		}
	}
	if err := b.template(ctx, b.cfg.Template); err != nil {
		return nil, fmt.Errorf("template: %w", err)
	}
	if err := b.licenses(ctx); err != nil {
		return nil, err
	}
	if err := b.write("NOTICE.md", []byte(b.notice()), rules.File{Kind: "notice"}); err != nil {
		return nil, err
	}
	if err := b.write("README.md", []byte(b.cfg.Readme), rules.File{Kind: "notice"}); err != nil {
		return nil, err
	}

	m := b.manifest()
	if err := b.checkShrink(m); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if _, err := rules.ParseManifest(data); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(b.out, rules.ManifestPath), append(data, '\n'), 0o644); err != nil {
		return nil, err
	}
	return b.changed(m), nil
}

// template mirrors the layout into the template: the configured groups, the layout's rules with
// every rule set replaced by its parts on the branch, and those parts as rule providers.
func (b *builder) template(ctx context.Context, t *tmpl) error {
	src, file, ok := b.cfg.sourceOf(t.Layout)
	if !ok {
		return fmt.Errorf("layout %s is not from a configured source", t.Layout)
	}
	body, err := b.read(ctx, src, file)
	if err != nil {
		return err
	}
	layout, err := parseLayout(body)
	if err != nil {
		return fmt.Errorf("layout %s: %w", t.Layout, err)
	}

	providers := &yaml.Node{Kind: yaml.MappingNode}
	files := map[string]string{} // provider name → file
	var ruleList []string
	var stats templateStats
	mapped := map[string]bool{}
	for _, rule := range layout.Rules {
		fields := rules.SplitRule(rule)
		// The policy: after MATCH, or after the payload.
		if i := min(len(fields)-1, 2); i > 0 && (i == 2 || strings.EqualFold(fields[0], "MATCH")) {
			if to, ok := t.Policies[fields[i]]; ok {
				mapped[fields[i]] = true
				fields[i] = to
			}
		}
		if !strings.EqualFold(fields[0], "RULE-SET") {
			ruleList = append(ruleList, strings.Join(fields, ","))
			continue
		}
		if len(fields) < 3 {
			return fmt.Errorf("rule %q has no policy", rule)
		}
		lp, ok := layout.Providers[fields[1]]
		if !ok {
			return fmt.Errorf("rule %q: no rule provider %s", rule, fields[1])
		}
		set, err := b.ruleSet(ctx, lp)
		if err != nil {
			return fmt.Errorf("rule provider %s: %w", fields[1], err)
		}
		for _, p := range set.parts {
			name := providerName(fields[1], set, p)
			if f, ok := files[name]; ok && f != p.file {
				return fmt.Errorf("two rule providers are named %s", name)
			} else if !ok {
				files[name] = p.file
				if err := addProvider(providers, name, rules.Provider{
					Type:     "http",
					Behavior: p.behavior,
					Format:   p.format,
					URL:      rules.Placeholder + "/" + p.file,
					Path:     b.cfg.ProviderPath + "/" + strings.TrimPrefix(p.file, "providers/"),
					Interval: b.cfg.Interval,
				}); err != nil {
					return err
				}
				stats.providers++
				stats.entries += len(p.entries)
				stats.bytes += b.files[p.file].Size
			}
			r := append([]string{"RULE-SET", name}, fields[2:]...)
			if p.noResolve && !slices.ContainsFunc(fields[3:], func(s string) bool { return strings.EqualFold(s, "no-resolve") }) {
				r = append(r, "no-resolve")
			}
			ruleList = append(ruleList, strings.Join(r, ","))
		}
	}

	for from := range t.Policies {
		if !mapped[from] {
			return fmt.Errorf("no rule sends traffic to %s any more; remove it from policies", from)
		}
	}
	data, err := renderTemplate(t, src, file, providers, ruleList)
	if err != nil {
		return err
	}
	if err := rules.Validate(data); err != nil {
		return err
	}
	if err := checkGroupsUsed(t.Groups, ruleList); err != nil {
		return err
	}
	if err := b.write(rules.TemplatePath, data, rules.File{Kind: "template", Source: src.fetchURL(file), License: src.License}); err != nil {
		return err
	}
	fmt.Fprintf(b.log, "template: %d rule providers, %d entries, %s\n", stats.providers, stats.entries, size(stats.bytes))
	return nil
}

// parseLayout reads a Clash rules file. dler-io's start with the rules' list items, under an
// implied "rules:".
func parseLayout(body []byte) (*layoutDoc, error) {
	var doc layoutDoc
	if err := yaml.Unmarshal(body, &doc); err != nil || doc.Rules == nil {
		doc = layoutDoc{}
		if err := yaml.Unmarshal(append([]byte("rules:\n"), body...), &doc); err != nil {
			return nil, err
		}
	}
	if len(doc.Rules) == 0 {
		return nil, fmt.Errorf("no rules")
	}
	return &doc, nil
}

// ruleSet downloads and converts a rule set once, however many rules use it.
func (b *builder) ruleSet(ctx context.Context, lp layoutProvider) (*ruleSet, error) {
	if set, ok := b.sets[lp.URL]; ok {
		if set.behavior != lp.Behavior {
			return nil, fmt.Errorf("%s: behavior %s here, %s elsewhere", lp.URL, lp.Behavior, set.behavior)
		}
		return set, nil
	}
	if lp.Type != "http" {
		return nil, fmt.Errorf("type %q", lp.Type)
	}
	src, file, ok := b.cfg.sourceOf(lp.URL)
	if !ok {
		return nil, fmt.Errorf("%s is not from a configured source", lp.URL)
	}
	fetchURL := src.fetchURL(file)
	body, err := b.read(ctx, src, file)
	if err != nil {
		return nil, err
	}
	lic := b.cfg.license(src.License)
	if name := licenseHeader(body); src.LicenseHeader && name != "" {
		if lic = b.cfg.licenseNamed(name); lic == nil {
			return nil, fmt.Errorf("%s: unknown license %q", fetchURL, name)
		}
	}
	parts, whole, dropped, err := parseRuleSet(body, lp.Behavior, lp.Format)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fetchURL, err)
	}
	if len(parts) > 1 && whole != nil && countEntries(parts)-countKind(parts, partClassical) < b.cfg.SplitMin {
		parts = []*part{whole}
	}
	base, err := outputBase(src, file)
	if err != nil {
		return nil, err
	}
	if other, ok := b.bases[base]; ok {
		return nil, fmt.Errorf("%s and %s both go to %s", other, lp.URL, base)
	}
	b.bases[base] = lp.URL
	set := &ruleSet{ref: lp.URL, src: src, path: file, base: base, license: lic, behavior: lp.Behavior, parts: parts, dropped: dropped}

	for _, p := range parts {
		meta := rules.File{Kind: "rule-set", Behavior: p.behavior, Entries: len(p.entries), Source: fetchURL, License: lic.ID}
		text := base + "." + p.kind + ".txt"
		meta.Format = "text"
		if err := b.write(text, ruleText(set, p), meta); err != nil {
			return nil, err
		}
		p.file, p.format = text, "text"
		if b.convert == nil || p.behavior == "classical" {
			continue
		}
		mrs := base + "." + p.kind + ".mrs"
		if err := b.convert(ctx, p.behavior, filepath.Join(b.out, text), filepath.Join(b.out, mrs)); err != nil {
			return nil, err
		}
		meta.Format = "mrs"
		if err := b.record(mrs, meta); err != nil {
			return nil, err
		}
		p.file, p.format = mrs, "mrs"
	}
	var left []string
	for _, kind := range sortedKeys(dropped) {
		left = append(left, fmt.Sprintf("%d %s", dropped[kind], kind))
	}
	note := ""
	if len(left) > 0 {
		note = ", left out " + strings.Join(left, ", ")
	}
	fmt.Fprintf(b.log, "  %s: %d entries%s\n", base, countEntries(parts), note)
	b.sets[lp.URL] = set
	return set, nil
}

// read returns a file of a source, from its archive if it has one.
func (b *builder) read(ctx context.Context, src *source, file string) ([]byte, error) {
	if src.Archive == "" {
		return b.fetch.get(ctx, src.fetchURL(file), nil)
	}
	if src.files == nil {
		u := strings.ReplaceAll(src.Archive, "{commit}", src.commit)
		files, err := b.fetch.archive(ctx, u)
		if err != nil {
			return nil, err
		}
		src.files = files
	}
	data, ok := src.files[file]
	switch {
	case !ok:
		return nil, fmt.Errorf("%s: no %s", src.Name, file)
	case data == nil:
		return nil, fmt.Errorf("%s: %s is larger than %d bytes", src.Name, file, b.cfg.MaxSize)
	}
	if err := checkText(data); err != nil {
		return nil, fmt.Errorf("%s: %s: %w", src.Name, file, err)
	}
	return data, nil
}

func addProvider(providers *yaml.Node, name string, p rules.Provider) error {
	var value yaml.Node
	if err := value.Encode(p); err != nil {
		return err
	}
	for i := 0; i < len(value.Content); i += 2 {
		if value.Content[i].Value == "url" {
			value.Content[i+1].Style = yaml.DoubleQuotedStyle
		}
	}
	providers.Content = append(providers.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: name}, &value)
	return nil
}

func renderTemplate(t *tmpl, src *source, layout string, providers *yaml.Node, ruleList []string) ([]byte, error) {
	var groups yaml.Node
	if err := groups.Encode(t.Groups); err != nil {
		return nil, err
	}
	for _, g := range groups.Content {
		for i := 0; i < len(g.Content); i += 2 {
			if g.Content[i].Value == "proxies" {
				g.Content[i+1].Style = yaml.FlowStyle
			}
		}
	}
	var list yaml.Node
	if err := list.Encode(ruleList); err != nil {
		return nil, err
	}
	key := func(k string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Value: k} }
	doc := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		key("proxy-groups"), &groups,
		key("rule-providers"), providers,
		key("rules"), &list,
	}}
	doc.HeadComment = fmt.Sprintf("OpenWeir routing template, mirroring %s %s.\n%s\n"+
		"Groups reach nodes through include-all and filter; %s is the URL of the rules branch.\n"+
		"Schema: https://github.com/openweir/subconv/blob/main/docs/rules.md",
		src.Name, layout, strings.TrimSpace(t.Description), rules.Placeholder)
	var out strings.Builder
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	// Emoji in group names, as themselves rather than escaped.
	return model.Readable([]byte(out.String())), nil
}

// checkGroupsUsed refuses groups that no rule reaches, directly or through other groups.
func checkGroupsUsed(groups []rules.Group, ruleList []string) error {
	members := map[string][]string{}
	for _, g := range groups {
		members[g.Name] = g.Proxies
	}
	used := map[string]bool{}
	var use func(name string)
	use = func(name string) {
		if used[name] {
			return
		}
		used[name] = true
		for _, m := range members[name] {
			use(m)
		}
	}
	for _, r := range ruleList {
		fields := rules.SplitRule(r)
		if strings.EqualFold(fields[0], "MATCH") {
			use(fields[1])
		} else if len(fields) > 2 {
			use(fields[2])
		}
	}
	for _, g := range groups {
		if !used[g.Name] {
			return fmt.Errorf("group %s is not used by any rule", g.Name)
		}
	}
	return nil
}

// licenses ships the text of every license a file is under, where the license has one.
func (b *builder) licenses(ctx context.Context) error {
	for _, id := range b.licenseIDs() {
		lic := b.cfg.license(id)
		if lic.Text == "" {
			continue
		}
		text, err := b.fetch.get(ctx, lic.Text, nil)
		if err != nil {
			return fmt.Errorf("license %s: %w", id, err)
		}
		if err := b.write("LICENSES/"+id+".txt", text, rules.File{Kind: "license", Source: lic.Text, License: id}); err != nil {
			return err
		}
	}
	return nil
}

func (b *builder) licenseIDs() []string {
	var ids []string
	for _, f := range b.files {
		if f.License != "" && !slices.Contains(ids, f.License) {
			ids = append(ids, f.License)
		}
	}
	slices.Sort(ids)
	return ids
}

// notice attributes every source: where it is, under which license, and which files deviate
// from the source's license. It names no commit or date, which the manifest holds, so that it
// changes only with what it says.
func (b *builder) notice() string {
	var s strings.Builder
	s.WriteString(strings.TrimSpace(b.cfg.Notice) + "\n")
	for _, src := range b.cfg.Sources {
		var exceptions []string
		used := false
		for _, set := range b.sets {
			if set.src != src {
				continue
			}
			used = true
			if set.license.ID != src.License {
				exceptions = append(exceptions, fmt.Sprintf("- `%s.*`: %s", set.base, set.license.ID))
			}
		}
		if !used {
			continue
		}
		fmt.Fprintf(&s, "\n## %s\n\n<%s>. License: %s.\n\n%s\n", src.Name, src.Home, src.License, strings.TrimSpace(src.Notice))
		if len(exceptions) > 0 {
			slices.Sort(exceptions)
			fmt.Fprintf(&s, "\nFiles under another license, as their headers state:\n\n%s\n", strings.Join(exceptions, "\n"))
		}
	}
	s.WriteString("\n## Licenses\n\n")
	for _, id := range b.licenseIDs() {
		lic := b.cfg.license(id)
		switch {
		case lic.Text != "":
			fmt.Fprintf(&s, "- %s: [LICENSES/%s.txt](LICENSES/%s.txt)\n", id, id, id)
		case lic.URI != "":
			fmt.Fprintf(&s, "- %s: <%s>\n", id, lic.URI)
		default:
			fmt.Fprintf(&s, "- %s: see the source's notice above\n", id)
		}
	}
	return s.String()
}

// write stores a file of the branch and records it for the manifest.
func (b *builder) write(path string, data []byte, meta rules.File) error {
	full := filepath.Join(b.out, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		return err
	}
	return b.record(path, meta)
}

func (b *builder) record(path string, meta rules.File) error {
	if !rules.ValidPath(path) {
		return fmt.Errorf("output path %q", path)
	}
	if _, ok := b.files[path]; ok {
		return fmt.Errorf("%s written twice", path)
	}
	data, err := os.ReadFile(filepath.Join(b.out, filepath.FromSlash(path)))
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return fmt.Errorf("%s is empty", path)
	}
	sum := sha256.Sum256(data)
	day := b.now.Format(time.DateOnly)
	meta.Path, meta.Size, meta.SHA256, meta.Updated = path, int64(len(data)), hex.EncodeToString(sum[:]), day
	if meta.Source != "" {
		meta.Retrieved = day
	}
	b.files[path] = &meta
	return nil
}

func (b *builder) manifest() *rules.Manifest {
	m := &rules.Manifest{
		Version:   b.now.Unix(),
		Generated: b.now.UTC().Format(time.RFC3339),
	}
	if b.prev != nil && m.Version <= b.prev.Version {
		m.Version = b.prev.Version + 1
	}
	for _, f := range b.files {
		if b.prev != nil {
			if old, ok := b.prev.File(f.Path); ok && old.SHA256 == f.SHA256 {
				f.Updated = old.Updated
			}
		}
		m.Files = append(m.Files, *f)
	}
	slices.SortFunc(m.Files, func(a, c rules.File) int { return strings.Compare(a.Path, c.Path) })
	for _, src := range b.cfg.Sources {
		m.Sources = append(m.Sources, rules.Source{Name: src.Name, Home: src.Home, Commit: src.commit, License: src.License})
	}
	return m
}

// checkShrink refuses a rule set that lost more than MaxShrink of its entries since the previous
// build: more likely a broken upstream than a cleanup.
func (b *builder) checkShrink(m *rules.Manifest) error {
	if b.prev == nil {
		return nil
	}
	for _, f := range m.Files {
		old, ok := b.prev.File(f.Path)
		if ok && old.Entries > 0 && float64(f.Entries) < float64(old.Entries)*(1-b.cfg.MaxShrink) {
			return fmt.Errorf("%s shrank from %d to %d entries", f.Path, old.Entries, f.Entries)
		}
	}
	return nil
}

// changed lists the paths whose content differs from the previous manifest, or that it does not
// list any more, with the manifest last; nothing when no file changed.
func (b *builder) changed(m *rules.Manifest) []string {
	var paths []string
	for _, f := range m.Files {
		if b.prev == nil {
			paths = append(paths, f.Path)
		} else if old, ok := b.prev.File(f.Path); !ok || old.SHA256 != f.SHA256 {
			paths = append(paths, f.Path)
		}
	}
	if b.prev != nil {
		for _, old := range b.prev.Files {
			if _, ok := m.File(old.Path); !ok {
				paths = append(paths, old.Path)
			}
		}
	}
	if len(paths) == 0 {
		return nil
	}
	return append(paths, rules.ManifestPath)
}

func size(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
