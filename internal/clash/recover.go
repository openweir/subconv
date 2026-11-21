package clash

import (
	"fmt"
	"strings"

	"github.com/openweir/subconv/internal/model"
)

// Recover reads a Clash config whose YAML does not parse as a whole, one top-level section at a
// time and, in a list that does not parse, one item at a time. A broken item is left out with
// a warning; the rest converts.
func Recover(text []byte) (model.Object, []model.Warning) {
	// YAML forbids tabs in indentation, which hand-edited configs carry; a tab is taken as four
	// spaces, as editors show it.
	lines := strings.Split(string(text), "\n")
	for index, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if indent := line[:len(line)-len(trimmed)]; strings.Contains(indent, "\t") {
			lines[index] = strings.ReplaceAll(indent, "\t", "    ") + trimmed
		}
	}
	if value, err := model.Decode([]byte(strings.Join(lines, "\n"))); err == nil && model.AsObject(value) != nil {
		return model.AsObject(value), nil
	}
	var config model.Object
	var warnings []model.Warning
	for _, section := range blocks(lines, 0) {
		value, err := model.Decode([]byte(strings.Join(section.lines, "\n")))
		if err == nil {
			for _, field := range model.AsObject(value) {
				config.Set(field.Key, field.Value)
			}
			continue
		}
		key, _, _ := strings.Cut(section.lines[0], ":")
		key = strings.TrimSpace(key)
		items, ok := listItems(section.lines[1:])
		if !ok {
			warnings = append(warnings, model.Warning{Code: model.WarnInvalidProxy, Detail: fmt.Sprintf("%s (line %d): not YAML", key, section.start+1)})
			continue
		}
		var list []any
		for _, item := range items {
			value, err := model.Decode([]byte(item.text))
			if err != nil {
				warnings = append(warnings, model.Warning{Code: code(key), Detail: fmt.Sprintf("%s item at line %d: not YAML", key, section.start+item.line+2)})
				continue
			}
			list = append(list, value)
		}
		config.Set(key, list)
	}
	return config, warnings
}

type block struct {
	start int
	lines []string
}

// blocks splits lines at the keys of the given indentation.
func blocks(lines []string, indent int) []block {
	var out []block
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if len(out) > 0 {
				out[len(out)-1].lines = append(out[len(out)-1].lines, line)
			}
			continue
		}
		if leading(line) == indent && !strings.HasPrefix(trimmed, "- ") && strings.Contains(trimmed, ":") {
			out = append(out, block{start: index, lines: []string{line}})
		} else if len(out) > 0 {
			out[len(out)-1].lines = append(out[len(out)-1].lines, line)
		}
	}
	return out
}

type item struct {
	line int
	text string
}

// listItems splits a block list into its items, each as YAML of its own: "- a: 1\n  b: 2"
// becomes "a: 1\nb: 2".
func listItems(lines []string) ([]item, bool) {
	indent := -1
	var out []item
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indent < 0 {
			if !strings.HasPrefix(trimmed, "-") {
				return nil, false
			}
			indent = leading(line)
		}
		if leading(line) == indent && strings.HasPrefix(trimmed, "-") {
			out = append(out, item{line: index, text: strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))})
			continue
		}
		if len(out) == 0 || leading(line) <= indent {
			return nil, false
		}
		// A continuation line, aligned with the first key after "- ".
		cut := min(indent+2, leading(line))
		out[len(out)-1].text += "\n" + line[cut:]
	}
	return out, indent >= 0
}

func leading(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

func code(section string) string {
	switch strings.ToLower(section) {
	case "proxy-groups", "proxy group":
		return model.WarnUnsupportedGroup
	case "rules", "rule":
		return model.WarnUnsupportedRule
	}
	return model.WarnInvalidProxy
}
