package jsoninput

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Reject ambiguous input before encoding/json can discard duplicate keys,
// accept case aliases, or replace invalid Unicode with U+FFFD.
func Validate(raw []byte, t reflect.Type) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("JSON must be valid UTF-8")
	}
	if err := validSurrogates(raw); err != nil {
		return err
	}
	var walk func(*json.Decoder, int) error
	walk = func(d *json.Decoder, depth int) error {
		if depth > 16 {
			return fmt.Errorf("JSON nesting exceeds 16 levels")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok {
					return fmt.Errorf("invalid object key")
				}
				if seen[key] {
					return fmt.Errorf("duplicate key %s", key)
				}
				seen[key] = true
				if err := walk(d, depth+1); err != nil {
					return err
				}
			}
		} else if delim == '[' {
			for d.More() {
				if err := walk(d, depth+1); err != nil {
					return err
				}
			}
		} else {
			return fmt.Errorf("unexpected token")
		}
		end, err := d.Token()
		if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return fmt.Errorf("invalid closing delimiter")
		}
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := walk(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("multiple JSON values")
	}
	var required func([]byte, reflect.Type, string) error
	required = func(b []byte, t reflect.Type, path string) error {
		if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
			return fmt.Errorf("%s: null is not allowed", path)
		}
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			var items []json.RawMessage
			if err := json.Unmarshal(b, &items); err != nil {
				return fmt.Errorf("%s: expected an array", path)
			}
			if len(items) > 256 {
				return fmt.Errorf("%s: at most 256 items", path)
			}
			for i, item := range items {
				if err := required(item, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
			return nil
		}
		if t.Kind() != reflect.Struct {
			return nil
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			return fmt.Errorf("%s: expected an object", path)
		}
		allowed := map[string]bool{}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			key := strings.Split(field.Tag.Get("json"), ",")[0]
			if field.PkgPath != "" || key == "-" {
				continue
			}
			if key == "" {
				key = field.Name
			}
			allowed[key] = true
			v, ok := fields[key]
			if !ok {
				return fmt.Errorf("%s.%s: required field missing", path, key)
			}
			if err := required(v, field.Type, path+"."+key); err != nil {
				return err
			}
		}
		for key := range fields {
			if !allowed[key] {
				return fmt.Errorf("%s.%s: unknown field; use exact property names", path, key)
			}
		}
		return nil
	}
	return required(raw, t, "input")
}

// Isolated escaped surrogates would otherwise alias a literal replacement rune.
func validSurrogates(raw []byte) error {
	quoted := false
	hex4 := func(start int) (uint64, error) {
		if start+4 > len(raw) {
			return 0, fmt.Errorf("incomplete Unicode escape")
		}
		return strconv.ParseUint(string(raw[start:start+4]), 16, 16)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return fmt.Errorf("incomplete escape")
		}
		if raw[i] != 'u' {
			continue
		}
		v, err := hex4(i + 1)
		if err != nil {
			return err
		}
		i += 4
		if v >= 0xDC00 && v <= 0xDFFF {
			return fmt.Errorf("isolated low surrogate")
		}
		if v >= 0xD800 && v <= 0xDBFF {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return fmt.Errorf("unpaired high surrogate")
			}
			low, err := hex4(i + 3)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return fmt.Errorf("unpaired high surrogate")
			}
			i += 6
		}
	}
	return nil
}

// Decode validates the original JSON bytes before assigning any typed values.
func Decode(raw []byte, out any, maxBytes int) error {
	if len(raw) == 0 || len(raw) > maxBytes {
		return fmt.Errorf("JSON must be 1..%d bytes", maxBytes)
	}
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer || reflect.ValueOf(out).IsNil() {
		return fmt.Errorf("decode destination must be a non-nil pointer")
	}
	if err := Validate(raw, t.Elem()); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("one JSON value is required")
	}
	return nil
}
