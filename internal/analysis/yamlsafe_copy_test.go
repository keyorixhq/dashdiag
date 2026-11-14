package analysis

// yamlsafe_copy_test.go is a TEST-ONLY copy of internal/yamlsafe as proposed
// on branch chore/yaml-go-yaml-in (commit cb9cc021, "fix(policy): reject
// duplicate YAML keys in linear time before decoding (#1179)"). That package
// is not on main yet; copying it here lets FuzzPolicyYAMLDupKeyDifferential
// exercise the exact hardening path LoadPolicy will call once #1179 lands,
// against the same library it will run on (go.yaml.in/yaml/v3, already in
// this module's graph at v3.0.5; its decode.go is byte-identical to the
// v3.0.6 the branch pins).
//
// Keep the body identical to the branch. If #1179 merges, delete this file
// and point the fuzz target at the real package.

import (
	"fmt"

	goyaml "go.yaml.in/yaml/v3"
)

func yamlsafeUnmarshal(data []byte, v any) error {
	var root goyaml.Node
	if err := goyaml.Unmarshal(data, &root); err != nil {
		return err
	}
	if root.Kind == 0 {
		return nil // empty input: nothing to decode, v stays as it was
	}
	if err := yamlsafeCheckDuplicateKeys(&root); err != nil {
		return err
	}
	return root.Decode(v)
}

func yamlsafeCheckDuplicateKeys(n *goyaml.Node) error {
	return yamlsafeWalk(n, 0)
}

const yamlsafeMaxDepth = 10000

func yamlsafeWalk(n *goyaml.Node, depth int) error {
	if n == nil {
		return nil
	}
	if depth > yamlsafeMaxDepth {
		return fmt.Errorf("line %d: document is nested too deeply", n.Line)
	}
	if n.Kind == goyaml.MappingNode {
		seen := make(map[any]int, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind == goyaml.AliasNode && k.Alias != nil {
				k = k.Alias
			}
			if k.Kind == goyaml.ScalarNode && k.Tag != "!!merge" {
				var key any
				if err := k.Decode(&key); err == nil {
					if first, dup := seen[key]; dup {
						return fmt.Errorf("line %d: mapping key %q already defined at line %d", n.Content[i].Line, k.Value, first)
					}
					seen[key] = n.Content[i].Line
				}
			}
			if err := yamlsafeWalk(n.Content[i], depth+1); err != nil {
				return err
			}
			if err := yamlsafeWalk(n.Content[i+1], depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, c := range n.Content {
		if err := yamlsafeWalk(c, depth+1); err != nil {
			return err
		}
	}
	return nil
}
