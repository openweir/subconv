package subconv

import (
	"bytes"
	"errors"
	"strings"
	"unicode"

	"github.com/openweir/subconv/internal/body"
	"github.com/openweir/subconv/internal/links"
	"github.com/openweir/subconv/internal/model"
)

var (
	// ErrUnknownFormat is returned for input that is none of the formats.
	ErrUnknownFormat = errors.New("not a subscription in a format subconv reads")
	// ErrEmpty is returned for an empty body.
	ErrEmpty = errors.New("an empty subscription")
	// ErrWebPage is returned for an HTML page, which servers send for errors, logins and
	// challenges instead of a subscription.
	ErrWebPage = errors.New("a web page, not a subscription")
	// ErrMessage is returned for a short text or JSON message instead of a subscription, such
	// as an expired token's; the error includes the message.
	ErrMessage = errors.New("a message, not a subscription")
)

// inputError is one of the specific errors, which is also ErrUnknownFormat.
type inputError struct {
	kind   error
	detail string
}

func (e *inputError) Error() string {
	if e.detail != "" {
		return e.kind.Error() + ": " + e.detail
	}
	return e.kind.Error()
}

func (e *inputError) Is(target error) bool { return target == e.kind || target == ErrUnknownFormat }

// detect returns a body's format and the text to convert: decoded from Base64 or UTF-16, and
// without JSON comments.
func detect(data []byte, depth int) (Format, []byte, error) {
	text := bytes.TrimFunc(body.Clean(data), func(r rune) bool { return unicode.IsSpace(r) || r == '\uFEFF' })
	switch {
	case len(text) == 0:
		return "", nil, &inputError{kind: ErrEmpty}
	case body.WebPage(text):
		return "", nil, &inputError{kind: ErrWebPage}
	}
	var message string
	if bytes.HasPrefix(text, []byte("//")) || bytes.HasPrefix(text, []byte("/*")) {
		// JSON with a leading comment.
		if cleaned := bytes.TrimSpace(body.JSONC(text)); len(cleaned) > 0 {
			text = cleaned
		}
	}
	if text[0] == '{' || text[0] == '[' {
		cleaned := body.JSONC(text)
		if value, err := model.Decode(cleaned); err == nil {
			if format := jsonFormat(value); format != "" {
				return format, cleaned, nil
			}
			message = jsonMessage(value)
		}
	}
	if clashYAML(text) {
		return FormatClash, text, nil
	}
	if links.Is(text) {
		return FormatLinks, text, nil
	}
	if depth == 0 {
		if decoded, ok := body.Base64Text(text); ok {
			if format, payload, err := detect(decoded, 1); err == nil {
				return format, payload, nil
			}
		}
	}
	if message == "" && text[0] != '{' && text[0] != '[' {
		message = body.Message(text)
	}
	if message != "" {
		return "", nil, &inputError{kind: ErrMessage, detail: message}
	}
	return "", nil, ErrUnknownFormat
}

// jsonFormat names the format of a JSON config, or "".
func jsonFormat(value any) Format {
	config := model.AsObject(value)
	switch {
	case config.Value("outbounds") != nil || config.Value("endpoints") != nil:
		return FormatSingBox
	case config.Value("proxies") != nil || config.Value("proxy-providers") != nil:
		return FormatClash
	}
	return ""
}

// jsonMessage reads the message of a JSON error, as panels send them.
func jsonMessage(value any) string {
	config := model.AsObject(value)
	for _, key := range []string{"message", "msg", "error", "detail", "reason", "errors", "info"} {
		if text, ok := config.Value(key).(string); ok && text != "" {
			return body.Message([]byte(text))
		}
		if nested := model.AsObject(config.Value(key)); nested != nil {
			if text := jsonMessage(nested); text != "" {
				return text
			}
		}
	}
	return ""
}

// clashYAML reports a YAML mapping with Clash's proxies or providers, in any of the spellings
// Clash has used.
func clashYAML(text []byte) bool {
	if !bytes.Contains(text, []byte("roxies")) && !bytes.Contains(text, []byte("roxy")) {
		return false
	}
	value, err := model.Decode(text)
	if err != nil {
		return false
	}
	for _, field := range model.AsObject(value) {
		switch strings.ToLower(field.Key) {
		case "proxies", "proxy", "proxy-providers":
			return true
		}
	}
	return false
}
