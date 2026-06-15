package render

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// schema/dsd-output.json is the published contract for `dsd health --json` and
// the frozen platform API surface for 1.x (see COMPATIBILITY.md). It is hand-
// maintained, so it can silently drift from the JSONOutput struct that actually
// produces the output — which is exactly how it rotted to the v0.1.0 shape
// before. These tests fail when the struct and the schema disagree, in either
// direction, so the published contract can't go stale unnoticed.
//
// They deliberately use only the stdlib (no JSON-Schema validator dependency):
// they compare the set of JSON field names the structs emit against the set of
// property names the schema declares, per object. That catches the drift that
// matters (a field added/removed/renamed without updating the schema) without
// pulling in a validation library.

const schemaPath = "../../schema/dsd-output.json"

// jsonSchema is the minimal subset of draft-07 we need to walk property names.
type jsonSchema struct {
	Type       string                `json:"type"`
	Properties map[string]jsonSchema `json:"properties"`
	Items      *jsonSchema           `json:"items"`
	Required   []string              `json:"required"`
}

func loadSchema(t *testing.T) jsonSchema {
	t.Helper()
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("reading %s: %v", schemaPath, err)
	}
	var s jsonSchema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("%s is not valid JSON: %v", schemaPath, err)
	}
	return s
}

// jsonFieldNames returns the wire field names a struct emits (honoring json
// tags, skipping "-" and embedded/anonymous unwrapping we don't use here).
func jsonFieldNames(rt reflect.Type) []string {
	var names []string
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names
}

func keysOf(m map[string]jsonSchema) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func subset(t *testing.T, label string, got, declared []string) {
	t.Helper()
	declaredSet := map[string]bool{}
	for _, d := range declared {
		declaredSet[d] = true
	}
	for _, g := range got {
		if !declaredSet[g] {
			t.Errorf("%s: struct emits field %q but schema/dsd-output.json does not declare it — "+
				"add it to the schema (or the field is a breaking change to the 1.x contract)", label, g)
		}
	}
}

func superset(t *testing.T, label string, got, declared []string) {
	t.Helper()
	gotSet := map[string]bool{}
	for _, g := range got {
		gotSet[g] = true
	}
	for _, d := range declared {
		if !gotSet[d] {
			t.Errorf("%s: schema declares property %q but the struct no longer emits it — "+
				"remove it from schema/dsd-output.json (or the struct change dropped a 1.x contract field)", label, d)
		}
	}
}

// TestSchemaInSync_TopLevel checks the root object's properties match JSONOutput.
func TestSchemaInSync_TopLevel(t *testing.T) {
	s := loadSchema(t)
	got := jsonFieldNames(reflect.TypeOf(JSONOutput{}))
	declared := keysOf(s.Properties)
	subset(t, "top-level", got, declared)
	superset(t, "top-level", got, declared)
}

// TestSchemaInSync_Counts checks the counts object matches JSONCounts.
func TestSchemaInSync_Counts(t *testing.T) {
	s := loadSchema(t)
	countsSchema := s.Properties["counts"]
	got := jsonFieldNames(reflect.TypeOf(JSONCounts{}))
	declared := keysOf(countsSchema.Properties)
	subset(t, "counts", got, declared)
	superset(t, "counts", got, declared)
}

// TestSchemaInSync_Checks checks each checks[] item matches JSONCheck.
// `raw` is intentionally excluded from the contract (unconstrained in the
// schema), but the schema still declares the property name, so it round-trips.
func TestSchemaInSync_Checks(t *testing.T) {
	s := loadSchema(t)
	itemSchema := s.Properties["checks"].Items
	if itemSchema == nil {
		t.Fatal("schema checks.items is missing")
	}
	got := jsonFieldNames(reflect.TypeOf(JSONCheck{}))
	declared := keysOf(itemSchema.Properties)
	subset(t, "checks[]", got, declared)
	superset(t, "checks[]", got, declared)
}

// TestSchemaInSync_Insights checks each insights[] item matches JSONInsight.
func TestSchemaInSync_Insights(t *testing.T) {
	s := loadSchema(t)
	itemSchema := s.Properties["insights"].Items
	if itemSchema == nil {
		t.Fatal("schema insights.items is missing")
	}
	got := jsonFieldNames(reflect.TypeOf(JSONInsight{}))
	declared := keysOf(itemSchema.Properties)
	subset(t, "insights[]", got, declared)
	superset(t, "insights[]", got, declared)
}

// TestSchemaInSync_RequiredFieldsExist guards against a required[] entry that
// names a property the schema doesn't even declare (a copy-paste/rename slip).
func TestSchemaInSync_RequiredFieldsExist(t *testing.T) {
	s := loadSchema(t)
	check := func(label string, obj jsonSchema) {
		for _, req := range obj.Required {
			if _, ok := obj.Properties[req]; !ok {
				t.Errorf("%s: schema lists %q as required but does not declare it as a property", label, req)
			}
		}
	}
	check("top-level", s)
	check("counts", s.Properties["counts"])
	if it := s.Properties["checks"].Items; it != nil {
		check("checks[]", *it)
	}
	if it := s.Properties["insights"].Items; it != nil {
		check("insights[]", *it)
	}
}
