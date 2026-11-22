// Package normalize turns the parts every format converts to into a config OpenWeir mihomo
// loads: each proxy repaired or left out, unique names, providers a client may use, groups
// whose members exist and do not loop, and rules whose policies and rule sets exist. Whatever
// it leaves out or changes gets a warning; valid items keep their content and order.
package normalize

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/proxy"
)

// Policies mihomo defines itself. GLOBAL is a group a config may define; rules may always name it.
var builtIn = []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE"}

type state struct {
	r       *model.Result
	options model.Options
	// Names that exist: proxies and groups.
	proxies map[string]model.Object
	groups  map[string]bool
	// Names of proxies, groups and providers left out; references to them go quietly.
	dropped          map[string]bool
	providers        map[string]bool
	droppedProviders map[string]bool
	ruleSets         map[string]bool
	droppedRuleSets  map[string]bool
	// References already warned about.
	warned map[string]bool
	// Group filters compiled so far.
	filters map[string]Filter
}

// Result normalizes r in place.
func Result(r *model.Result, options model.Options) {
	s := &state{
		r:                r,
		options:          options,
		proxies:          map[string]model.Object{},
		groups:           map[string]bool{},
		dropped:          map[string]bool{},
		providers:        map[string]bool{},
		droppedProviders: map[string]bool{},
		ruleSets:         map[string]bool{},
		droppedRuleSets:  map[string]bool{},
		warned:           map[string]bool{},
	}
	r.Proxies = s.proxyList(r.Proxies, "proxy", s.proxies)
	s.proxyProviders()
	s.groupList()
	s.dialers()
	s.ruleProviders()
	s.rules()
}

// proxyList normalizes proxies and gives them unique names, recording them in names.
func (s *state) proxyList(list []model.Object, label string, names map[string]model.Object) []model.Object {
	out := make([]model.Object, 0, len(list))
	for index, raw := range list {
		name := proxy.Name(raw)
		at := name
		if at == "" {
			at = fmt.Sprintf("%s %d", label, index+1)
		}
		p, removed, problem := proxy.Normalize(raw)
		for _, option := range removed {
			s.r.Warn(model.WarnIgnoredOption, "%s: %s", at, option)
		}
		if problem != nil {
			s.r.Warn(problem.Code, "%s: %s", at, problem.Reason)
			if name != "" {
				s.dropped[name] = true
			}
			continue
		}
		if name == "" {
			name = p.String("type") + " " + p.String("server")
		}
		unique := s.unique(name, name == "GLOBAL", names)
		if unique != name {
			s.r.Warn(model.WarnRenamed, "%s: renamed %s", at, unique)
		}
		if _, set := p.Get("name"); set {
			p.Set("name", unique)
		} else {
			p = append(model.Object{{Key: "name", Value: unique}}, p...)
		}
		names[unique] = p
		out = append(out, p)
	}
	return out
}

// unique returns name, or name with a number, so that it names nothing yet. A reserved name
// always gets a number.
func (s *state) unique(name string, reserved bool, taken map[string]model.Object) string {
	used := func(candidate string) bool {
		_, proxy := taken[candidate]
		return proxy || s.groups[candidate] || slices.Contains(builtIn, candidate)
	}
	if !reserved && !used(name) {
		return name
	}
	for n := 2; ; n++ {
		if candidate := name + " " + strconv.Itoa(n); !used(candidate) {
			return candidate
		}
	}
}

// exists reports a name a group member or dialer-proxy may use.
func (s *state) exists(name string) bool {
	_, proxy := s.proxies[name]
	return proxy || s.groups[name] || slices.Contains(builtIn, name)
}

// seconds reads a number of seconds written as a number or a duration ("1h").
func seconds(value any) (int, bool) {
	if i, ok := model.Int(value); ok && i >= 0 {
		return i, true
	}
	text, _ := value.(string)
	if d, err := time.ParseDuration(strings.TrimSpace(text)); err == nil && d >= 0 {
		return int(d / time.Second), true
	}
	return 0, false
}

// badRegex reports a regular expression mihomo refuses. mihomo compiles group and provider
// filters with regexp2 and its default options, and regex rules with IgnoreCase: a group filter
// it cannot compile crashes it, a provider filter or a rule makes it refuse the config. A filter
// is compiled part by part, the parts separated by backquotes, and whole, as mihomo joins the
// filters of a provider's groups with | for its health checks; for that, a pattern must not
// leave the x or n option on at its end either, which would change the patterns after it.
func badRegex(pattern string) bool {
	if parts := strings.Split(pattern, "`"); len(parts) > 1 {
		for _, part := range parts {
			if _, err := compileRegex(part, regexp2.None); err != nil {
				return true
			}
		}
	}
	if _, err := compileRegex(pattern, regexp2.IgnoreCase); err != nil {
		return true
	}
	whole, err := compileRegex(pattern, regexp2.None)
	if err != nil {
		return true
	}
	// With x on, "#)" is a comment and the parenthesis is missing; with n on, "()" captures
	// nothing.
	joined, err := compileRegex(pattern+"|(#)", regexp2.None)
	return err != nil || len(joined.GetGroupNumbers()) == len(whole.GetGroupNumbers())
}

// compileRegex compiles a pattern with regexp2, as mihomo does.
func compileRegex(pattern string, options regexp2.RegexOptions) (re *regexp2.Regexp, err error) {
	defer func() {
		if recover() != nil {
			re, err = nil, fmt.Errorf("regexp2 panics on %q", pattern)
		}
	}()
	return regexp2.Compile(pattern, options)
}

// texts reads a list of strings, or one string, as a list.
func texts(value any) []string {
	var out []string
	for _, item := range model.AsList(value) {
		if text, ok := model.Text(item); ok && text != "" {
			out = append(out, text)
		}
	}
	return out
}

func toAny(list []string) []any {
	out := make([]any, len(list))
	for index, item := range list {
		out[index] = item
	}
	return out
}

// headers turns an HTTP header map into the lists mihomo's providers take.
func headers(value any) model.Object {
	var out model.Object
	for _, field := range model.AsObject(value) {
		if values := texts(field.Value); len(values) > 0 {
			out = append(out, model.Field{Key: field.Key, Value: toAny(values)})
		}
	}
	return out
}

// Proxies normalizes the proxies of a proxy provider's content on their own. Their dialer-proxy
// names the config the provider joins, so it stays as written; groups, providers and rules in
// the content are not the provider's and go.
func Proxies(r *model.Result) {
	s := &state{
		r:       r,
		proxies: map[string]model.Object{},
		groups:  map[string]bool{},
		dropped: map[string]bool{},
		warned:  map[string]bool{},
	}
	r.Proxies = s.proxyList(r.Proxies, "proxy", s.proxies)
	r.ProxyProviders, r.Groups, r.RuleProviders, r.Rules = nil, nil, nil, nil
	r.RuleStats = model.RuleStats{}
}
