package artifactnumeric

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// These full typed expectations were hand-declared independently and frozen
// before the candidate source, generator or activity was executed.
func TestInt64BoundsIndependentNativeLiterals(t *testing.T) {
	raw, err := os.ReadFile("testdata/int64-bound-literals.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalogue struct {
		Cases []struct {
			ID       string   `json:"id"`
			Input    Facts    `json:"input"`
			Expected Decision `json:"expected"`
		} `json:"cases"`
	}
	if json.Unmarshal(raw, &catalogue) != nil || len(catalogue.Cases) != 17 {
		t.Fatal("independent literal catalogue unavailable")
	}
	bindings, err := SourceBindings()
	if err != nil {
		t.Fatal(err)
	}
	observations := make([]struct {
		ID     string `json:"id"`
		Actual Proof  `json:"actual"`
	}, 0, len(catalogue.Cases))
	for _, tc := range catalogue.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			actual, err := Evaluate(tc.Input)
			if err != nil || actual.Facts != tc.Input || actual.Decision != tc.Expected || actual.Bindings != bindings {
				t.Fatalf("full native proof differs from independent typed literal: %#v, %v", actual, err)
			}
			observations = append(observations, struct {
				ID     string `json:"id"`
				Actual Proof  `json:"actual"`
			}{tc.ID, actual})
		})
	}
	if output := os.Getenv("GOOO_INT64_NATIVE_PROOF_PATH"); output != "" {
		if t.Failed() || len(observations) != 17 {
			t.Fatal("cannot record incomplete native observations")
		}
		proof := struct {
			Schema          string `json:"schema"`
			CatalogueSHA256 string `json:"catalogue_sha256"`
			Observations    any    `json:"observations"`
		}{"policy-studio/int64-native-observations/v1", hash(raw), observations}
		encoded, err := json.MarshalIndent(proof, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, append(encoded, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInt64BoundsActualProjectionBindings(t *testing.T) {
	bindings, err := SourceBindings()
	if err != nil || bindings.Schema != BindingsSchema || bindings.CompilerSourceSHA != CompilerSourcePin {
		t.Fatalf("actual source bindings unavailable: %v", err)
	}
	for name, got := range map[string]string{
		"source.gooo":        bindings.SourceSHA256,
		"rules_generated.go": bindings.GeneratedSHA256,
		"bridge.go":          bindings.BridgeSHA256,
		"model.go":           bindings.ModelSHA256,
		"bindings.go":        bindings.BindingsSHA256,
		"generator.txt":      bindings.GeneratorSHA256,
		"generation.json":    bindings.GenerationSHA256,
	} {
		raw, err := os.ReadFile(name)
		if err != nil || got != hash(raw) {
			t.Fatalf("binding does not identify actual %s: %v", name, err)
		}
	}
	if !reflect.DeepEqual(rulesBytes, generatedBytes) || !reflect.DeepEqual(bridgeSource, bridgeBytes) {
		t.Fatal("generated or bridge retained copy differs")
	}
}

func TestInt64BoundsBindingFailures(t *testing.T) {
	for _, name := range []string{"source", "rules", "bridge", "model", "host", "generator", "receipt", "pin"} {
		t.Run(name, func(t *testing.T) {
			source, rules, bridge, model, host, generator, receipt, pin := sourceBytes, rulesBytes, bridgeSource, modelSource, bindingsSource, generatorBytes, generationBytes, compilerPin
			switch name {
			case "source":
				source = append(append([]byte{}, source...), '\n')
			case "rules":
				rules = append(append([]byte{}, rules...), '\n')
			case "bridge":
				bridge = append(append([]byte{}, bridge...), '\n')
			case "model":
				model = append(append([]byte{}, model...), '\n')
			case "host":
				host = append(append([]byte{}, host...), '\n')
			case "generator":
				generator = append(append([]byte{}, generator...), '\n')
			case "receipt":
				receipt = []byte(`{"schema":null}`)
			case "pin":
				pin = "0000000000000000000000000000000000000000"
			}
			if _, err := checkBindings(source, rules, generatedBytes, bridge, bridgeBytes, model, host, generator, receipt, pin); err == nil {
				t.Fatal("unavailable or changed projection binding was accepted")
			}
		})
	}
}

func TestInt64BoundsCheckedBindingsFailClosed(t *testing.T) {
	if _, err := SourceBindings(); err != nil {
		t.Fatal(err)
	}
	t.Run("actual asset inputs", func(t *testing.T) {
		for index := 0; index < 10; index++ {
			assets := [][]byte{sourceBytes, rulesBytes, generatedBytes, bridgeSource, bridgeBytes, modelSource, bindingsSource, generatorBytes, generationBytes, []byte(compilerPin)}
			assets[index] = append(append([]byte{}, assets[index]...), byte('x'))
			if _, err := checkBindings(assets[0], assets[1], assets[2], assets[3], assets[4], assets[5], assets[6], assets[7], assets[8], string(assets[9])); err == nil {
				t.Fatalf("accepted changed bound asset %d", index)
			}
		}
	})
	t.Run("full compiler and activity provenance", func(t *testing.T) {
		for _, change := range []func(map[string]any){
			func(v map[string]any) { delete(v, "compiler") },
			func(v map[string]any) { v["untrusted"] = true },
			func(v map[string]any) { v["compiler"].(map[string]any)["vcs_modified"] = "true" },
			func(v map[string]any) {
				v["compiler"].(map[string]any)["compiler_source_sha"] = "0000000000000000000000000000000000000000"
			},
			func(v map[string]any) {
				v["activity"].(map[string]any)["report"].(map[string]any)["typecheck_passed"] = false
			},
			func(v map[string]any) {
				v["activity"].(map[string]any)["report"].(map[string]any)["generated_digest"] = "sha256:" + string(bytes.Repeat([]byte{'0'}, 64))
			},
			func(v map[string]any) { v["activity"].(map[string]any)["source"] = "package artifactnumeric\n" },
		} {
			value, err := object(generationBytes)
			if err != nil {
				t.Fatal(err)
			}
			change(value)
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := checkBindings(sourceBytes, rulesBytes, generatedBytes, bridgeSource, bridgeBytes, modelSource, bindingsSource, generatorBytes, raw, compilerPin); err == nil {
				t.Fatal("accepted tampered complete generation provenance")
			}
		}
	})
	t.Run("missing bindings prevent native result", func(t *testing.T) {
		original := generationBytes
		t.Cleanup(func() { generationBytes = original })
		generationBytes = []byte("{}")
		if _, err := SourceBindings(); err == nil {
			t.Fatal("bindings unavailable but accepted")
		}
		proof, err := Evaluate(Facts{0, 0, "gte"})
		if err == nil || !reflect.DeepEqual(proof, Proof{}) {
			t.Fatal("native proof emitted despite unavailable bindings")
		}
	})
}
