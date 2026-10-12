package httpapp

import (
	"github.com/kimjooyoon/gooo-policy-studio/internal/jsoninput"
	"reflect"
)

func completeJSON(raw []byte, t reflect.Type) error { return jsoninput.Validate(raw, t) }
