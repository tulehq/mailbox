package authz

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// reference is the part of AWS's service reference JSON for ses
// (https://servicereference.us-east-1.amazonaws.com/v1/ses/ses.json) the
// tests read: each action's resource types and condition keys. The copy in
// testdata keeps those fields of every action.
type reference struct {
	Actions []struct {
		Name                string
		Resources           []string
		ActionConditionKeys []string
	}
}

func loadReference(t *testing.T) map[string]struct {
	resources, keys []string
} {
	t.Helper()
	b, err := os.ReadFile("testdata/ses-service-reference.json")
	if err != nil {
		t.Fatalf("read the reference: %v", err)
	}
	var ref reference
	if err = json.Unmarshal(b, &ref); err != nil {
		t.Fatalf("decode the reference: %v", err)
	}
	out := make(map[string]struct{ resources, keys []string }, len(ref.Actions))
	for _, a := range ref.Actions {
		out["ses:"+a.Name] = struct{ resources, keys []string }{a.Resources, a.ActionConditionKeys}
	}
	return out
}

// referenceTypes are the reference's names of the resource types.
var referenceTypes = map[ResourceType]string{
	Identity:             "identity",
	SenderIdentity:       "identity",
	HeaderSenderIdentity: "identity",
	ConfigurationSet:     "configuration-set",
	Template:             "template",
}

func TestEveryEntryIsTheReferences(t *testing.T) {
	ref := loadReference(t)
	for _, op := range operations {
		if op.Action == InspectAction {
			if !strings.HasPrefix(op.Path, "/_mailbox/") || len(op.Keys) != 0 {
				t.Errorf("%s: tule:Inspect is for the retrieval API alone, with no keys", op.Name)
			}
			continue
		}
		a, ok := ref[op.Action]
		if !ok {
			t.Errorf("%s: %s is not an action of the reference", op.Name, op.Action)
			continue
		}
		if op.Action != "ses:"+op.Name {
			t.Errorf("%s: evaluated as %s", op.Name, op.Action)
		}
		checkResources(t, op, a.resources)
		checkKeyNames(t, op, a.keys)
	}
}

// checkResources fails unless op is evaluated on the resource types the
// reference lists for its action.
func checkResources(t *testing.T, op Operation, want []string) {
	t.Helper()
	types := make([]string, 0, len(op.Resources))
	for _, r := range op.Resources {
		name, known := referenceTypes[r.Type]
		if !known {
			t.Errorf("%s: resource type %d is not the reference's", op.Name, r.Type)
		}
		types = append(types, name)
	}
	slices.Sort(types)
	types = slices.Compact(types)
	if want = slices.Sorted(slices.Values(want)); !slices.Equal(types, want) {
		t.Errorf("%s: resource types %q, the reference's %q", op.Name, types, want)
	}
}

// checkKeyNames fails unless every key op supplies is one the reference
// lists for its action.
func checkKeyNames(t *testing.T, op Operation, listed []string) {
	t.Helper()
	for _, k := range op.Keys {
		if !slices.Contains(listed, k) {
			t.Errorf("%s: supplies %s, which the reference does not list", op.Name, k)
		}
		if k == KeyRequestTags && !slices.Contains(listed, "aws:TagKeys") {
			t.Errorf("%s: supplies aws:TagKeys, which the reference does not list", op.Name)
		}
	}
}

func TestTagResourceIsTheReferences(t *testing.T) {
	a, ok := loadReference(t)[tagAction]
	if !ok {
		t.Fatalf("%s is not an action of the reference", tagAction)
	}
	for _, typ := range []string{"identity", "template"} {
		if !slices.Contains(a.resources, typ) {
			t.Errorf("%s does not take %s", tagAction, typ)
		}
	}
	for _, k := range []string{KeyRequestTags, "aws:TagKeys", KeyAPIVersion} {
		if !slices.Contains(a.keys, k) {
			t.Errorf("%s does not list %s", tagAction, k)
		}
	}
}

func TestEveryEntryHasOneRoute(t *testing.T) {
	seen := map[string]bool{}
	for _, op := range operations {
		key := op.Method + " " + op.Path
		if seen[key] {
			t.Errorf("%s has two entries", key)
		}
		seen[key] = true
		if got, ok := Lookup(op.Method, op.Path); !ok || got.Name != op.Name {
			t.Errorf("Lookup(%s) = %v, %v", key, got.Name, ok)
		}
	}
}
