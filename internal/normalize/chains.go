package normalize

import (
	"regexp"
	"strings"

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
// dialer-proxy, or any member of a group.
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
		members := texts(o.Value("proxies"))
		if all, _ := o.Value("include-all").(bool); all || o.Value("include-all-proxies") == true {
			filter := o.String("filter")
			for name := range s.proxies {
				if matches(filter, name) {
					members = append(members, name)
				}
			}
		}
		for _, member := range members {
			if s.reaches(member, target, seen) {
				return true
			}
		}
	}
	return false
}

// matches applies a group filter as far as Go's regexp reads it; a pattern only mihomo's
// regexp2 reads counts as matching.
func matches(filter, name string) bool {
	if filter == "" {
		return true
	}
	for part := range strings.SplitSeq(filter, "`") {
		re, err := regexp.Compile(part)
		if err != nil || re.MatchString(name) {
			return true
		}
	}
	return false
}
