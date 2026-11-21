package model

import (
	"bytes"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// Readable writes the characters go-yaml escapes in double-quoted scalars, those outside the
// Basic Multilingual Plane such as emoji ("\U0001F680"), as themselves, which YAML allows. It
// leaves everything else as the encoder wrote it.
func Readable(yaml []byte) []byte {
	if !bytes.Contains(yaml, []byte(`\U`)) {
		return yaml
	}
	out := make([]byte, 0, len(yaml))
	quoted := false
	for index := 0; index < len(yaml); index++ {
		c := yaml[index]
		switch {
		case !quoted && c == '"' && tokenStart(yaml, index):
			quoted = true
		case quoted && c == '"':
			quoted = false
		case quoted && c == '\\':
			if index+9 < len(yaml) && yaml[index+1] == 'U' {
				if r, err := strconv.ParseUint(string(yaml[index+2:index+10]), 16, 32); err == nil &&
					utf8.ValidRune(rune(r)) && unicode.IsGraphic(rune(r)) {
					out = utf8.AppendRune(out, rune(r))
					index += 9
					continue
				}
			}
			// Another escape: copy it whole, so that an escaped quote or backslash stays one.
			out = append(out, c)
			if index+1 < len(yaml) {
				index++
				out = append(out, yaml[index])
			}
			continue
		}
		out = append(out, c)
	}
	return out
}

// tokenStart reports whether a quote at index opens a scalar: at the start of a line's content,
// or after "- ", ": ", "[", "{" or ", ".
func tokenStart(yaml []byte, index int) bool {
	before := bytes.TrimRight(yaml[:index], " ")
	if len(before) == 0 || before[len(before)-1] == '\n' {
		return true
	}
	switch before[len(before)-1] {
	case '[', '{':
		return true
	case ',', ':', '-', '?':
		return len(before) < index // followed by a space
	}
	return false
}
