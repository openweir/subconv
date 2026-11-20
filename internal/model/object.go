package model

import (
	"bytes"
	"encoding/json"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Field is one key of an Object.
type Field struct {
	Key   string
	Value any
}

// Object is a mapping that keeps its keys in order, so that converted configs read the way
// clients write them and test vectors compare byte for byte. Values are strings, numbers,
// booleans, []any, []string, Object or nil.
type Object []Field

// Set replaces the value of key, or appends it.
func (o *Object) Set(key string, value any) {
	for index := range *o {
		if (*o)[index].Key == key {
			(*o)[index].Value = value
			return
		}
	}
	*o = append(*o, Field{key, value})
}

// Value returns the value of key, or nil.
func (o Object) Value(key string) any {
	value, _ := o.Get(key)
	return value
}

// Get returns the value of key.
func (o Object) Get(key string) (any, bool) {
	for _, field := range o {
		if field.Key == key {
			return field.Value, true
		}
	}
	return nil, false
}

// String returns the value of key when it is a string.
func (o Object) String(key string) string {
	value, _ := o.Get(key)
	text, _ := value.(string)
	return text
}

// New returns an Object built from pairs, leaving out empty values: nil, "", false, 0,
// and empty lists and objects. Clients take a missing key as its default.
func New(pairs ...any) Object {
	out := make(Object, 0, len(pairs)/2)
	for index := 0; index+1 < len(pairs); index += 2 {
		key := pairs[index].(string)
		if !Empty(pairs[index+1]) {
			out = append(out, Field{key, pairs[index+1]})
		}
	}
	return out
}

func Empty(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case string:
		return v == ""
	case bool:
		return !v
	case int:
		return v == 0
	case float64:
		return v == 0
	case []any:
		return len(v) == 0
	case []string:
		return len(v) == 0
	case Object:
		return len(v) == 0
	}
	return false
}

// MarshalJSON writes the keys in order.
func (o Object) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, field := range o {
		if index > 0 {
			buffer.WriteByte(',')
		}
		key, err := json.Marshal(field.Key)
		if err != nil {
			return nil, err
		}
		value, err := json.Marshal(field.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field.Key, err)
		}
		buffer.Write(key)
		buffer.WriteByte(':')
		buffer.Write(value)
	}
	buffer.WriteByte('}')
	return buffer.Bytes(), nil
}

// MarshalYAML writes the keys in order.
func (o Object) MarshalYAML() (any, error) {
	node := &yaml.Node{Kind: yaml.MappingNode}
	for _, field := range o {
		value := &yaml.Node{}
		if err := value.Encode(field.Value); err != nil {
			return nil, fmt.Errorf("%s: %w", field.Key, err)
		}
		node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: field.Key}, value)
	}
	return node, nil
}

// fromNode converts decoded YAML (or JSON, which is YAML) into ordered values.
func fromNode(node *yaml.Node) (any, error) {
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 0 {
			return nil, nil
		}
		return fromNode(node.Content[0])
	case yaml.AliasNode:
		return fromNode(node.Alias)
	case yaml.MappingNode:
		out := make(Object, 0, len(node.Content)/2)
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			if key.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("line %d: a key that is not a scalar", key.Line)
			}
			if key.Value == "<<" {
				// A merge key: the merged mapping's fields, unless set here.
				merged, err := fromNode(node.Content[index+1])
				if err != nil {
					return nil, err
				}
				if fields, ok := merged.(Object); ok {
					for _, field := range fields {
						if _, set := out.Get(field.Key); !set {
							out = append(out, field)
						}
					}
				}
				continue
			}
			value, err := fromNode(node.Content[index+1])
			if err != nil {
				return nil, err
			}
			out.Set(key.Value, value)
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(node.Content))
		for _, item := range node.Content {
			value, err := fromNode(item)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
		}
		return out, nil
	default:
		var value any
		if err := node.Decode(&value); err != nil {
			return nil, err
		}
		// Integers stay ints and floats float64, as encoding/json would give numbers.
		if number, ok := value.(int64); ok {
			return int(number), nil
		}
		return value, nil
	}
}

// Decode parses YAML or JSON into ordered values.
func Decode(data []byte) (any, error) {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, err
	}
	return fromNode(&node)
}

// Accessors for decoded values.

func AsObject(value any) Object {
	o, _ := value.(Object)
	return o
}

func AsList(value any) []any {
	switch v := value.(type) {
	case []any:
		return v
	case nil:
		return nil
	default:
		// sing-box accepts a single value where it takes a list.
		return []any{v}
	}
}

func AsStrings(value any) []string {
	var out []string
	for _, item := range AsList(value) {
		switch v := item.(type) {
		case string:
			out = append(out, v)
		case int:
			out = append(out, fmt.Sprint(v))
		}
	}
	return out
}

func AsInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	}
	return 0
}

func AsBool(value any) bool {
	b, _ := value.(bool)
	return b
}
