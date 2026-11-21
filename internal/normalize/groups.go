package normalize

import (
	"slices"
	"strconv"
	"strings"

	"github.com/openweir/subconv/internal/model"
)

var groupAliases = map[string]string{
	"select":       "select",
	"selector":     "select",
	"static":       "select",
	"url-test":     "url-test",
	"urltest":      "url-test",
	"fallback":     "fallback",
	"available":    "fallback",
	"load-balance": "load-balance",
	"loadbalance":  "load-balance",
	"relay":        "relay",
}

type group struct {
	o    model.Object
	name string
	kind string
	// Members by name and providers by name, as resolved so far.
	proxies, use []string
}

// groupList normalizes the groups: types and options, unique names, relays as dialer-proxy
// chains, members and providers that exist, no loops, and no group left empty.
func (s *state) groupList() {
	var groups []*group
	for index, raw := range s.r.Groups {
		g := s.group(index, raw)
		if g == nil {
			continue
		}
		groups = append(groups, g)
		s.groups[g.name] = true
	}
	s.providerNames(groups)
	groups = s.relays(groups)
	for changed := true; changed; {
		changed = false
		for _, g := range groups {
			if !s.groups[g.name] {
				continue
			}
			s.members(g)
			if s.empty(g) {
				s.r.Warn(model.WarnEmptyGroup, "%s: no members left", g.name)
				delete(s.groups, g.name)
				s.dropped[g.name] = true
				changed = true
			}
		}
		if !changed {
			changed = s.breakCycle(groups)
		}
	}
	s.r.Groups = s.r.Groups[:0]
	for _, g := range groups {
		if !s.groups[g.name] {
			continue
		}
		s.fallback(g)
		if _, set := g.o.Get("proxies"); set || len(g.proxies) > 0 {
			g.o.Set("proxies", toAny(g.proxies))
		}
		if len(g.proxies) == 0 {
			g.o.Delete("proxies")
		}
		if _, set := g.o.Get("use"); set {
			if len(g.use) > 0 {
				g.o.Set("use", toAny(g.use))
			} else {
				g.o.Delete("use")
			}
		}
		s.r.Groups = append(s.r.Groups, g.o)
	}
}

// group normalizes one group's type, name and options.
func (s *state) group(index int, raw model.Object) *group {
	o := raw.Clone()
	name, _ := model.Text(o.Value("name"))
	at := name
	if at == "" {
		at = "group " + strconv.Itoa(index+1)
	}
	typeText, _ := model.Text(o.Value("type"))
	kind := groupAliases[strings.ReplaceAll(strings.ToLower(strings.TrimSpace(typeText)), "_", "-")]
	switch {
	case o == nil:
		s.r.Warn(model.WarnUnsupportedGroup, "%s: not a mapping", at)
		return nil
	case name == "":
		s.r.Warn(model.WarnUnsupportedGroup, "%s: no name", at)
		return nil
	case kind == "":
		s.r.Warn(model.WarnUnsupportedGroup, "%s: type %s", at, typeText)
		s.dropped[name] = true
		return nil
	}
	unique := name
	if _, proxy := s.proxies[name]; proxy || s.groups[name] || slices.Contains(builtIn, name) {
		unique = s.unique(name, false, s.proxies)
		s.r.Warn(model.WarnRenamed, "%s: renamed %s", at, unique)
	}
	o.Set("name", unique)
	o.Set("type", kind)
	for _, key := range []string{"dialer-proxy", "routing-mark", "interface-name"} {
		if _, set := o.Get(key); set {
			o.Delete(key)
			s.r.Warn(model.WarnIgnoredOption, "%s: %s belongs on proxies, not groups", unique, key)
		}
	}
	for _, key := range []string{"lazy", "disable-udp", "hidden", "include-all", "include-all-proxies", "include-all-providers"} {
		if value, set := o.Get(key); set {
			if b, ok := model.Bool(value); ok {
				o.Set(key, b)
			} else {
				o.Delete(key)
				s.r.Warn(model.WarnIgnoredOption, "%s: %s is not a boolean", unique, key)
			}
		}
	}
	for _, key := range []string{"interval", "timeout", "tolerance", "max-failed-times"} {
		s.interval(unique, &o, key)
	}
	for _, key := range []string{"filter", "exclude-filter"} {
		if value, set := o.Get(key); set {
			if text, ok := model.Text(value); ok && !badRegex(text) {
				o.Set(key, text)
			} else {
				o.Delete(key)
				s.r.Warn(model.WarnIgnoredOption, "%s: %s is not a valid regular expression", unique, key)
			}
		}
	}
	if status, set := o.Get("expected-status"); set {
		text, _ := model.Text(status)
		if strings.Trim(text, "0123456789/-* ") != "" {
			o.Delete("expected-status")
			s.r.Warn(model.WarnIgnoredOption, "%s: expected-status %s", unique, text)
		} else {
			o.Set("expected-status", text)
		}
	}
	if kind == "load-balance" {
		if value, set := o.Get("strategy"); set {
			text, _ := model.Text(value)
			strategy := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(text)), "_", "-")
			switch strategy {
			case "consistent-hashing", "round-robin", "sticky-sessions":
				o.Set("strategy", strategy)
			default:
				o.Delete("strategy")
				s.r.Warn(model.WarnIgnoredOption, "%s: strategy %s", unique, text)
			}
		}
		if o.String("strategy") == "round-robin" {
			if _, set := o.Get("hash-key"); set {
				o.Delete("hash-key")
				s.r.Warn(model.WarnIgnoredOption, "%s: hash-key does nothing with round-robin", unique)
			}
		}
	}
	return &group{o: o, name: unique, kind: kind, proxies: texts(o.Value("proxies")), use: texts(o.Value("use"))}
}

// providerNames renames proxy providers that share a group's name or mihomo's own, which mihomo
// refuses, and points the groups that use them at the new names.
func (s *state) providerNames(groups []*group) {
	for index, field := range s.r.ProxyProviders {
		if !s.groups[field.Key] && field.Key != reservedProvider {
			continue
		}
		renamed := field.Key
		for n := 2; s.groups[renamed] || s.providers[renamed] || renamed == reservedProvider; n++ {
			renamed = field.Key + " " + strconv.Itoa(n)
		}
		s.r.Warn(model.WarnRenamed, "%s: proxy provider renamed %s", field.Key, renamed)
		s.r.ProxyProviders[index].Key = renamed
		delete(s.providers, field.Key)
		s.providers[renamed] = true
		for _, g := range groups {
			for i, use := range g.use {
				if use == field.Key {
					g.use[i] = renamed
				}
			}
		}
	}
}

// members keeps the members and providers that exist, once each.
func (s *state) members(g *group) {
	var proxies []string
	for _, member := range g.proxies {
		switch {
		case slices.Contains(proxies, member):
		case s.exists(member):
			proxies = append(proxies, member)
		case !s.dropped[member] && !s.warned[g.name+"\x00"+member]:
			s.r.Warn(model.WarnUnknownReference, "%s: member %s", g.name, member)
			s.warned[g.name+"\x00"+member] = true
		}
	}
	g.proxies = proxies
	var use []string
	for _, provider := range g.use {
		switch {
		case slices.Contains(use, provider):
		case s.providers[provider]:
			use = append(use, provider)
		case !s.droppedProviders[provider] && !s.warned[g.name+"\x00"+provider]:
			s.r.Warn(model.WarnUnknownReference, "%s: provider %s", g.name, provider)
			s.warned[g.name+"\x00"+provider] = true
		}
	}
	g.use = use
}

// empty reports a group mihomo would refuse for having nothing to choose from.
func (s *state) empty(g *group) bool {
	flag := func(key string) bool { b, _ := g.o.Value(key).(bool); return b }
	return len(g.proxies) == 0 && len(g.use) == 0 && !flag("include-all") && !flag("include-all-proxies") &&
		!(flag("include-all-providers") && len(s.providers) > 0)
}

// breakCycle removes one member that makes groups contain each other, reporting whether it did.
func (s *state) breakCycle(groups []*group) bool {
	byName := map[string]*group{}
	for _, g := range groups {
		if s.groups[g.name] {
			byName[g.name] = g
		}
	}
	const visiting, done = 1, 2
	state := map[string]int{}
	var visit func(g *group) bool
	visit = func(g *group) bool {
		state[g.name] = visiting
		for _, member := range g.proxies {
			child := byName[member]
			if child == nil {
				continue
			}
			if state[member] == visiting {
				s.r.Warn(model.WarnCyclicReference, "%s: member %s leads back to it", g.name, member)
				g.proxies = slices.DeleteFunc(g.proxies, func(m string) bool { return m == member })
				return true
			}
			if state[member] == 0 && visit(child) {
				return true
			}
		}
		state[g.name] = done
		return false
	}
	for _, g := range groups {
		if byName[g.name] != nil && state[g.name] == 0 && visit(g) {
			return true
		}
	}
	return false
}

// fallback checks empty-fallback, which must name a proxy or a built-in policy.
func (s *state) fallback(g *group) {
	value, set := g.o.Get("empty-fallback")
	if !set {
		return
	}
	name, _ := model.Text(value)
	if _, proxy := s.proxies[name]; proxy || slices.Contains(builtIn, name) {
		return
	}
	g.o.Delete("empty-fallback")
	s.r.Warn(model.WarnIgnoredOption, "%s: empty-fallback %s is not a proxy", g.name, name)
}

// relays turns relay groups, which mihomo removed, into dialer-proxy chains: each hop after the
// first becomes a copy of its proxy that dials through the hop before, and the last copy takes
// the relay's name, so rules and groups that use the relay keep working.
func (s *state) relays(groups []*group) []*group {
	pending := map[string]*group{}
	for _, g := range groups {
		if g.kind == "relay" {
			pending[g.name] = g
		}
	}
	for progress := true; progress && len(pending) > 0; {
		progress = false
		for _, g := range groups {
			if pending[g.name] == nil || s.relayWaits(g, pending) {
				continue
			}
			delete(pending, g.name)
			progress = true
			s.relay(g)
		}
	}
	for _, g := range groups {
		if pending[g.name] != nil {
			s.dropGroup(g, model.WarnUnsupportedGroup, "a relay through another relay that cannot be chained")
		}
	}
	return slices.DeleteFunc(groups, func(g *group) bool { return g.kind == "relay" })
}

// relayWaits reports a relay whose later hops include a relay not converted yet.
func (s *state) relayWaits(g *group, pending map[string]*group) bool {
	for index, hop := range g.proxies {
		if index > 0 && pending[hop] != nil && hop != g.name {
			return true
		}
	}
	return false
}

func (s *state) relay(g *group) {
	if len(g.use) > 0 {
		s.dropGroup(g, model.WarnUnsupportedGroup, "a relay through a provider, which dialer-proxy cannot name")
		return
	}
	var hops []string
	for _, hop := range g.proxies {
		switch {
		case hop == "DIRECT":
		case !s.exists(hop) || hop == g.name:
			s.dropGroup(g, model.WarnUnsupportedGroup, "relay hop "+hop+" does not exist")
			return
		default:
			hops = append(hops, hop)
		}
	}
	switch len(hops) {
	case 0:
		s.dropGroup(g, model.WarnEmptyGroup, "no members left")
		return
	case 1:
		g.kind = "select"
		g.o.Set("type", "select")
		g.proxies = hops
		return
	}
	for _, hop := range hops[1:] {
		if s.proxies[hop] == nil {
			s.dropGroup(g, model.WarnUnsupportedGroup, "relay hop "+hop+" is not a proxy; dialer-proxy chains proxies")
			return
		}
	}
	// The relay's name goes to the last hop.
	delete(s.groups, g.name)
	previous := hops[0]
	for index, hop := range hops[1:] {
		name := g.name
		if index < len(hops)-2 {
			name = s.unique(g.name+" / "+hop, false, s.proxies)
		}
		copied := s.proxies[hop].Clone()
		copied.Set("name", name)
		copied.Set("dialer-proxy", previous)
		s.proxies[name] = copied
		s.r.Proxies = append(s.r.Proxies, copied)
		previous = name
	}
}

func (s *state) dropGroup(g *group, code, reason string) {
	s.r.Warn(code, "%s: %s", g.name, reason)
	delete(s.groups, g.name)
	s.dropped[g.name] = true
	g.kind = "relay" // removed with the relays
}
