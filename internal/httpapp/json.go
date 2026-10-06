package httpapp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Reject omitted/null fields and duplicate keys instead of converting them into zero values.
func completeJSON(raw []byte, t reflect.Type) error {
	var walk func(*json.Decoder) error
	walk = func(d *json.Decoder) error {
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
				key := k.(string)
				if seen[key] {
					return fmt.Errorf("duplicate key %s", key)
				}
				seen[key] = true
				if err := walk(d); err != nil {
					return err
				}
			}
		} else if delim == '[' {
			for d.More() {
				if err := walk(d); err != nil {
					return err
				}
			}
		} else {
			return fmt.Errorf("unexpected token")
		}
		_, err = d.Token()
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := walk(d); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("multiple JSON values")
	}
	var required func([]byte, reflect.Type) error
	required = func(b []byte, t reflect.Type) error {
		if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
			return fmt.Errorf("null field")
		}
		if t.Kind() != reflect.Struct {
			return nil
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			return err
		}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			key := strings.Split(field.Tag.Get("json"), ",")[0]
			v, ok := fields[key]
			if !ok {
				return fmt.Errorf("missing %s", key)
			}
			if err := required(v, field.Type); err != nil {
				return err
			}
		}
		return nil
	}
	return required(raw, t)
}
