package normalize

import (
	"slices"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/openweir/subconv/internal/model"
)

// dialers checks what proxies and providers dial through: a dialer-proxy must exist, and a chain
// must not lead back to its start, directly or through a group.
func (s *state) dialers() {
	for index := range s.r.Proxies {
		p := &s.r.Proxies[index]
		s.refer(p.String("name"), p, "dialer-proxy")
		s.proxies[p.String("name")] = *p
	}
	for index := range s.r.Proxies {
		p := &s.r.Proxies[index]
		name := p.String("name")
		if dialer := p.String("dialer-proxy"); dialer != "" && s.reaches(dialer, name, map[string]bool{}) {
			s.r.Warn(model.WarnCyclicReference, "%s: dialer-proxy %s leads back to it", name, dialer)
			p.Delete("dialer-proxy")
			s.proxies[name] = *p
		}
	}
	for index, field := range s.r.ProxyProviders {
		provider := model.AsObject(field.Value)
		s.refer(field.Key, &provider, "proxy")
		s.refer(field.Key, &provider, "dialer-proxy")
		if override := model.AsObject(provider.Value("override")); override != nil {
			s.refer(field.Key+" override", &override, "dialer-proxy")
			provider.Set("override", override)
		}
		s.r.ProxyProviders[index].Value = provider
	}
}

// reaches reports whether dialing through from can end up dialing target: through from's own
// dialer-proxy, or anything a group may choose.
func (s *state) reaches(from, target string, seen map[string]bool) bool {
	if from == target {
		return true
	}
	if seen[from] {
		return false
	}
	seen[from] = true
	if p, ok := s.proxies[from]; ok {
		next := p.String("dialer-proxy")
		return next != "" && s.reaches(next, target, seen)
	}
	for _, o := range s.r.Groups {
		if o.String("name") != from {
			continue
		}
		for _, member := range s.choices(o) {
			if s.reaches(member, target, seen) {
				return true
			}
		}
	}
	return false
}

// choices lists what a group may dial through, as mihomo builds it: its members and, with
// include-all, the config's proxies its filter matches; then without those its exclude-filter
// matches or whose type its exclude-type lists, which mihomo applies to every member; and its
// empty-fallback, which it dials when nothing is left. A filter that takes too long to tell
// counts as letting a proxy through.
func (s *state) choices(o model.Object) []string {
	members := texts(o.Value("proxies"))
	all, _ := model.Bool(o.Value("include-all"))
	proxies, _ := model.Bool(o.Value("include-all-proxies"))
	if all || proxies {
		filter := s.filter(o.String("filter"))
		for name := range s.proxies {
			if matched, err := filter.Match(name); filter == nil || matched || err != nil {
				members = append(members, name)
			}
		}
	}
	exclude, types := s.filter(o.String("exclude-filter")), o.String("exclude-type")
	members = slices.DeleteFunc(members, func(name string) bool {
		matched, _ := exclude.Match(name)
		return matched || types != "" && s.excludedType(types, name)
	})
	if fallback := o.String("empty-fallback"); fallback != "" {
		members = append(members, fallback)
	}
	return members
}

// filter compiles a group's filter once. One that does not compile, which groupList removed
// already, is no filter.
func (s *state) filter(pattern string) Filter {
	if f, ok := s.filters[pattern]; ok {
		return f
	}
	f, _ := CompileFilter(pattern)
	if s.filters == nil {
		s.filters = map[string]Filter{}
	}
	s.filters[pattern] = f
	return f
}

// excludedType reports a proxy or group whose type an exclude-type lists. mihomo compares its
// own names of the types, ignoring case: Shadowsocks for ss, Selector for select.
func (s *state) excludedType(types, name string) bool {
	kind := ""
	if p, ok := s.proxies[name]; ok {
		kind = p.String("type")
	} else {
		for _, o := range s.r.Groups {
			if o.String("name") == name {
				kind = o.String("type")
			}
		}
	}
	if kind == "" {
		return false
	}
	if mihomo, ok := typeNames[kind]; ok {
		kind = mihomo
	} else {
		kind = strings.ReplaceAll(kind, "-", "") // url-test is URLTest, vless-reverse VlessReverse
	}
	for excluded := range strings.SplitSeq(types, "|") {
		if strings.EqualFold(excluded, kind) {
			return true
		}
	}
	return false
}

// mihomo's names of the types that differ from the config's by more than case and dashes.
var typeNames = map[string]string{"ss": "Shadowsocks", "ssr": "ShadowsocksR", "select": "Selector"}

// matchTimeout bounds one filter match, which regexp2 may otherwise backtrack through for
// longer than a conversion should take.
const matchTimeout = 100 * time.Millisecond

// Filter is a group or provider filter as mihomo reads it: each part between backquotes a
// pattern of its own, compiled with regexp2 and its default options. It matches a name when
// one of its parts does.
type Filter []*regexp2.Regexp

// CompileFilter compiles a filter; "" is no filter, a nil Filter.
func CompileFilter(pattern string) (Filter, error) {
	if pattern == "" {
		return nil, nil
	}
	var f Filter
	for part := range strings.SplitSeq(pattern, "`") {
		re, err := compileRegex(part, regexp2.None)
		if err != nil {
			return nil, err
		}
		re.MatchTimeout = matchTimeout
		f = append(f, re)
	}
	return f, nil
}

// Match reports whether a part of the filter matches name. When none does but one took too
// long to tell, it returns that error; mihomo, which lets it run, might have found a match.
func (f Filter) Match(name string) (bool, error) {
	var slow error
	for _, re := range f {
		matched, err := re.MatchString(name)
		if matched {
			return true, nil
		}
		if err != nil {
			slow = err
		}
	}
	return false, slow
}
