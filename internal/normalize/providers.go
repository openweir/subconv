package normalize

import (
	"strings"

	"github.com/openweir/subconv/internal/model"
	"github.com/openweir/subconv/internal/proxy"
	"github.com/openweir/subconv/internal/ruleset"
)

// Provider names mihomo reserves.
const reservedProvider = "default"

// proxyProviders keeps the providers a client can use: http with a web URL, inline, and local
// files, which the client decides on. Cache paths of http providers are the client's, so they
// are removed.
func (s *state) proxyProviders() {
	var out model.Object
	for _, field := range s.r.ProxyProviders {
		name := field.Key
		provider, reason := s.proxyProvider(name, model.AsObject(field.Value))
		if provider == nil {
			s.r.Warn(model.WarnUnsupportedProvider, "%s: %s", name, reason)
			s.droppedProviders[name] = true
			continue
		}
		out = append(out, model.Field{Key: name, Value: provider})
		s.providers[name] = true
	}
	s.r.ProxyProviders = out
}

func (s *state) proxyProvider(name string, p model.Object) (model.Object, string) {
	if p == nil {
		return nil, "not a mapping"
	}
	if name == reservedProvider {
		return nil, "the name is mihomo's own"
	}
	p = p.Clone()
	kind := providerType(p)
	switch kind {
	case "http":
		if !ruleset.WebURL(p.String("url")) {
			return nil, "no web URL"
		}
		p.Delete("path")
	case "inline":
		var payload []model.Object
		for _, item := range model.AsList(p.Value("payload")) {
			if o := model.AsObject(item); o != nil {
				payload = append(payload, o)
			}
		}
		names := map[string]model.Object{}
		kept := s.proxyList(payload, name+" proxy", names)
		if len(kept) == 0 {
			return nil, "no usable proxies"
		}
		p.Set("payload", toAnyObjects(kept))
	case "file":
		if p.String("path") == "" {
			return nil, "a local file without a path"
		}
		s.r.Warn(model.WarnLocalProvider, "%s: %s", name, p.String("path"))
	default:
		return nil, "type " + kind
	}
	p.Set("type", kind)
	s.interval(name, &p, "interval")
	for _, key := range []string{"filter", "exclude-filter", "exclude-type"} {
		if value, set := p.Get(key); set {
			text, ok := model.Text(value)
			if !ok || key != "exclude-type" && badRegex(text) {
				p.Delete(key)
				s.r.Warn(model.WarnIgnoredOption, "%s: %s is not a valid regular expression", name, key)
				continue
			}
			p.Set(key, text)
		}
	}
	if value, set := p.Get("header"); set {
		p.Set("header", headers(value))
	}
	if check := model.AsObject(p.Value("health-check")); check != nil {
		check = check.Clone()
		for _, key := range []string{"enable", "lazy"} {
			if value, ok := check.Value(key).(string); ok {
				b, _ := model.Bool(value)
				check.Set(key, b)
			}
		}
		s.interval(name+" health-check", &check, "interval")
		s.interval(name+" health-check", &check, "timeout")
		p.Set("health-check", check)
	}
	if override := model.AsObject(p.Value("override")); override != nil {
		override = override.Clone()
		for _, key := range []string{"interface-name", "routing-mark"} {
			if _, set := override.Get(key); set {
				override.Delete(key)
				s.r.Warn(model.WarnIgnoredOption, "%s: override %s is the client's setting", name, key)
			}
		}
		p.Set("override", override)
	}
	return p, ""
}

// ruleProviders keeps the rule sets mihomo can read and a client may download.
func (s *state) ruleProviders() {
	var out model.Object
	for _, field := range s.r.RuleProviders {
		name := field.Key
		provider, reason := s.ruleProvider(name, model.AsObject(field.Value))
		if provider == nil {
			s.r.Warn(model.WarnUnsupportedRuleSet, "%s: %s", name, reason)
			s.droppedRuleSets[name] = true
			continue
		}
		s.refer(name, &provider, "proxy")
		out = append(out, model.Field{Key: name, Value: provider})
		s.ruleSets[name] = true
	}
	s.r.RuleProviders = out
}

func (s *state) ruleProvider(name string, p model.Object) (model.Object, string) {
	if p == nil {
		return nil, "not a mapping"
	}
	p = p.Clone()
	kind := providerType(p)
	behavior := ruleset.Behavior(p.String("behavior"))
	if behavior == "" {
		return nil, "behavior " + p.String("behavior")
	}
	p.Set("behavior", behavior)
	format := ruleset.Format(p.String("format"))
	switch kind {
	case "http":
		url := strings.TrimSpace(p.String("url"))
		if !ruleset.WebURL(url) {
			return nil, "no web URL"
		}
		p.Set("url", url)
		if format == "" {
			// mihomo reads a provider without a format as YAML, which .txt and .list files
			// often are (Loyalsoldier's payload lists); only a binary or sing-box extension
			// says otherwise.
			switch inferred := ruleset.FormatOf(url); inferred {
			case "mrs", "srs", "json":
				format = inferred
			}
		}
		if format == "srs" || format == "json" {
			// sing-box's formats: a well-known set has a MetaCubeX twin; the plugin converts
			// source JSON itself.
			interval, _ := seconds(p.Value("interval"))
			if twin, ok := ruleset.MetaCubeX(url, name, interval); ok {
				return twin, ""
			}
			if format == "json" && s.options.ConvertsRuleSets {
				format = "text"
			} else {
				return nil, "a sing-box rule set mihomo cannot read"
			}
		}
		p.Delete("path")
		p.Delete("path-in-bundle")
	case "inline":
		// An empty set is a set that matches nothing, as in mihomo; its rules stay.
		p.Set("payload", toAny(texts(p.Value("payload"))))
		format = ""
	case "file":
		if p.String("path") == "" {
			return nil, "a local file without a path"
		}
		s.r.Warn(model.WarnLocalProvider, "%s: %s", name, p.String("path"))
	default:
		return nil, "type " + kind
	}
	p.Set("type", kind)
	switch format {
	case "":
		p.Delete("format")
	case "yaml", "text", "mrs":
		if format == "mrs" && behavior == "classical" {
			return nil, "a classical rule set in MRS, which holds domains or IP ranges only"
		}
		p.Set("format", format)
	default:
		return nil, "format " + p.String("format")
	}
	s.interval(name, &p, "interval")
	if value, set := p.Get("header"); set {
		p.Set("header", headers(value))
	}
	return p, ""
}

// providerType reads a provider's type, inferring it from what the provider holds when missing.
func providerType(p model.Object) string {
	kind := strings.ToLower(strings.TrimSpace(p.String("type")))
	if kind == "" {
		switch {
		case p.String("url") != "":
			kind = "http"
		case p.Value("payload") != nil:
			kind = "inline"
		case p.String("path") != "":
			kind = "file"
		}
	}
	return kind
}

// interval converts a number of seconds written as a duration ("1h"); mihomo reads numbers and
// numeric strings itself, and anything else goes.
func (s *state) interval(at string, p *model.Object, key string) {
	value, set := p.Get(key)
	if !set || proxy.AcceptedInt(value) {
		return
	}
	if n, ok := seconds(value); ok {
		p.Set(key, n)
		return
	}
	p.Delete(key)
	s.r.Warn(model.WarnIgnoredOption, "%s: %s is not a number of seconds", at, key)
}

// refer removes a reference to a proxy or group that does not exist.
func (s *state) refer(at string, p *model.Object, key string) {
	name := p.String(key)
	if name == "" {
		return
	}
	if !s.exists(name) {
		p.Delete(key)
		s.r.Warn(model.WarnUnknownReference, "%s: %s %s", at, key, name)
	}
}

func toAnyObjects(list []model.Object) []any {
	out := make([]any, len(list))
	for index, o := range list {
		out[index] = o
	}
	return out
}
