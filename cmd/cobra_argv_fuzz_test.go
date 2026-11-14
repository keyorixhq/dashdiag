package cmd

// cobra_argv_fuzz_test.go — FuzzCobraArgvMetamorphic: argv handling through
// the real spf13/cobra command resolution (Find/stripFlags, Traverse of
// persistent flags) and spf13/pflag parsing, against dsd's REAL command tree
// and flag definitions (names, shorthands, types, NoOptDefVal, Args
// validators), copied into a fresh replica tree per parse so no global flag
// state leaks between renderings. Who controls the bytes: whoever builds the
// argv — the operator, but also scripts and CI wrappers that splice in
// untrusted values (a hostname, an endpoint list) as flag values.
//
// Oracles (metamorphic): one logical invocation — subcommand, a set of flag
// assignments, positionals — rendered several equivalent ways must resolve to
// the same command path, the same positionals and the same parsed flag
// values (Value.String()), or fail in every rendering:
//   - `--f=v` vs `--f v` (space form only for flags without NoOptDefVal);
//   - flags before vs after positionals (pflag interspersed mode);
//   - shuffled flag order, and shorthand forms (`-x v`, `-xv`, bare `-b`);
//   - integer values written in decimal vs 0x-hex (pflag parses base 0);
//   - root persistent flags placed before the subcommand name;
//   - `--` before positionals: anything after it, even "-x", is positional.
// Secret echo: when a string flag carries a sentinel and an unrelated unknown
// flag makes the parse fail, neither the returned error nor anything cobra
// writes to stdout/stderr contains the sentinel.
//
// What this does NOT verify: the command bodies (RunE is replaced by a
// recorder); PersistentPreRun side effects (applyNetworkPolicy etc.); flag
// types the replica cannot clone (anything outside bool/string/int/int64/
// uint/float64/duration/stringSlice/stringArray/intSlice/count is left out
// of generation and of comparison); repeated occurrences of one flag (slice
// append order is legitimately order-dependent); `-h/--help` and shell
// completion; the echo of a value inside the very token that failed (pflag
// quotes the failing token by design, e.g. "unknown shorthand flag 'z' in
// -zVALUE").

import (
	"bytes"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const argvSentinel = "argv-S3NT1NEL-hunter2"

type argvResult struct {
	err   bool
	path  string
	args  []string
	flags map[string]string
}

type argvRecorder struct{ res *argvResult }

// cloneFlag creates a fresh flag with the same name/shorthand/type/default/
// NoOptDefVal in fs. ok=false for types the replica does not support.
func cloneFlag(fs *pflag.FlagSet, f *pflag.Flag) bool {
	n, s, u := f.Name, f.Shorthand, f.Usage
	switch f.Value.Type() {
	case "bool":
		d, _ := strconv.ParseBool(f.DefValue)
		fs.BoolP(n, s, d, u)
	case "string":
		fs.StringP(n, s, f.DefValue, u)
	case "int":
		d, _ := strconv.Atoi(f.DefValue)
		fs.IntP(n, s, d, u)
	case "int64":
		d, _ := strconv.ParseInt(f.DefValue, 10, 64)
		fs.Int64P(n, s, d, u)
	case "uint":
		d, _ := strconv.ParseUint(f.DefValue, 10, 64)
		fs.UintP(n, s, uint(d), u)
	case "float64":
		d, _ := strconv.ParseFloat(f.DefValue, 64)
		fs.Float64P(n, s, d, u)
	case "duration":
		d, _ := time.ParseDuration(f.DefValue)
		fs.DurationP(n, s, d, u)
	case "stringSlice":
		fs.StringSliceP(n, s, nil, u)
	case "stringArray":
		fs.StringArrayP(n, s, nil, u)
	case "intSlice":
		fs.IntSliceP(n, s, nil, u)
	case "count":
		fs.CountP(n, s, u)
	default:
		return false
	}
	nf := fs.Lookup(n)
	nf.NoOptDefVal = f.NoOptDefVal
	nf.Hidden = f.Hidden
	return true
}

// replicaTree mirrors real's command tree with fresh flags and a recording RunE.
func replicaTree(real *cobra.Command, rec *argvRecorder) *cobra.Command {
	r := &cobra.Command{
		Use:     real.Use,
		Aliases: real.Aliases,
		Args:    real.Args,
	}
	if real.Runnable() {
		r.RunE = func(c *cobra.Command, args []string) error {
			fl := map[string]string{}
			c.Flags().Visit(func(f *pflag.Flag) { fl[f.Name] = f.Value.String() })
			*rec.res = argvResult{path: c.CommandPath(), args: slices.Clone(args), flags: fl}
			return nil
		}
	}
	real.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) { cloneFlag(r.Flags(), f) })
	real.PersistentFlags().VisitAll(func(f *pflag.Flag) { cloneFlag(r.PersistentFlags(), f) })
	for _, c := range real.Commands() {
		if c.Name() == "help" || c.Name() == "completion" {
			continue
		}
		r.AddCommand(replicaTree(c, rec))
	}
	return r
}

func runArgv(argv []string) (argvResult, string) {
	var res argvResult
	rec := &argvRecorder{res: &res}
	root := replicaTree(rootCmd, rec)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(argv)
	root.SilenceUsage = false
	if err := root.Execute(); err != nil {
		return argvResult{err: true}, out.String() + "\n" + err.Error()
	}
	return res, out.String()
}

type leafCmd struct {
	path []string
	cmd  *cobra.Command
}

func runnableLeaves(c *cobra.Command, prefix []string, out *[]leafCmd) {
	for _, sc := range c.Commands() {
		if sc.Name() == "help" || sc.Name() == "completion" {
			continue
		}
		p := append(slices.Clone(prefix), sc.Name())
		if sc.Runnable() {
			*out = append(*out, leafCmd{path: p, cmd: sc})
		}
		runnableLeaves(sc, p, out)
	}
}

var argvSupported = map[string]bool{
	"bool": true, "string": true, "int": true, "int64": true, "uint": true, "float64": true,
	"duration": true, "stringSlice": true, "stringArray": true, "intSlice": true, "count": true,
}

type argvAssign struct {
	f          *pflag.Flag
	value      string // canonical value text (empty = bare flag for NoOptDefVal)
	alt        string // equivalent alternative text (hex for ints), or ""
	rootPersis bool
}

type argvCursor struct{ b []byte }

func (c *argvCursor) u8() byte {
	if len(c.b) == 0 {
		return 0
	}
	v := c.b[0]
	c.b = c.b[1:]
	return v
}

func (c *argvCursor) str(max int) string {
	l := min(int(c.u8())%(max+1), len(c.b))
	s := string(c.b[:l])
	c.b = c.b[l:]
	return s
}

func genValue(c *argvCursor, f *pflag.Flag) (val, alt string) {
	switch f.Value.Type() {
	case "bool":
		if c.u8()%2 == 0 {
			return "", "true" // bare flag == --f=true
		}
		return "false", ""
	case "count":
		return "", ""
	case "int", "int64":
		v := int64(int16(uint16(c.u8())<<8 | uint16(c.u8())))
		if v >= 0 {
			return strconv.FormatInt(v, 10), "0x" + strconv.FormatInt(v, 16)
		}
		return strconv.FormatInt(v, 10), ""
	case "uint":
		v := uint64(c.u8())
		return strconv.FormatUint(v, 10), "0x" + strconv.FormatUint(v, 16)
	case "float64":
		return strconv.FormatFloat(float64(int8(c.u8()))/4, 'g', -1, 64), ""
	case "duration":
		return strconv.Itoa(int(c.u8())) + "ms", ""
	case "intSlice":
		return strconv.Itoa(int(c.u8())) + "," + strconv.Itoa(int(c.u8())), ""
	}
	return c.str(12), ""
}

func FuzzCobraArgvMetamorphic(f *testing.F) {
	f.Add(uint16(0), []byte{2, 0, 1, 1, 5, 'h', 'e', 'l', 'l', 'o'}, uint64(1), false)
	f.Add(uint16(3), []byte{3, 1, 2, 3, 4, 5, 6, 7, 8, 9}, uint64(7), true)
	f.Add(uint16(5), []byte{1, 0, 0, 3, '-', 'x', 'y'}, uint64(3), false)
	f.Add(uint16(9), []byte{4, 9, 9, 9, 3, '=', 'a', '='}, uint64(99), true)
	f.Add(uint16(1), []byte{2, 0, 0, 1, 2, '-', '-'}, uint64(5), false)

	var leaves []leafCmd
	runnableLeaves(rootCmd, nil, &leaves)
	if len(leaves) == 0 {
		f.Fatal("premise: dsd has no runnable subcommands")
	}

	f.Fuzz(func(t *testing.T, which uint16, data []byte, seed uint64, secret bool) {
		leaf := leaves[int(which)%len(leaves)]
		cur := &argvCursor{b: data}

		// Candidate flags: everything this leaf parses, of a supported type.
		var cands []*pflag.Flag
		rootPersistent := map[string]bool{}
		rootCmd.PersistentFlags().VisitAll(func(fl *pflag.Flag) { rootPersistent[fl.Name] = true })
		seen := map[string]bool{}
		add := func(fl *pflag.Flag) {
			if !seen[fl.Name] && argvSupported[fl.Value.Type()] && fl.Name != "help" {
				seen[fl.Name] = true
				cands = append(cands, fl)
			}
		}
		leaf.cmd.LocalFlags().VisitAll(add)
		leaf.cmd.InheritedFlags().VisitAll(add)

		var assigns []argvAssign
		used := map[string]bool{}
		for n := int(cur.u8() % 4); n > 0 && len(cands) > 0; n-- {
			fl := cands[int(cur.u8())%len(cands)]
			if used[fl.Name] {
				continue
			}
			used[fl.Name] = true
			v, alt := genValue(cur, fl)
			assigns = append(assigns, argvAssign{f: fl, value: v, alt: alt, rootPersis: rootPersistent[fl.Name]})
		}
		var pos []string
		for n := int(cur.u8() % 3); n > 0; n-- {
			pos = append(pos, cur.str(8))
		}
		dashPos := false
		for _, p := range pos {
			if strings.HasPrefix(p, "-") || p == "" {
				dashPos = true
			}
		}

		eqForm := func(a argvAssign) []string {
			if a.value == "" && a.f.NoOptDefVal != "" {
				return []string{"--" + a.f.Name}
			}
			return []string{"--" + a.f.Name + "=" + a.value}
		}
		spaceForm := func(a argvAssign) []string {
			if a.f.NoOptDefVal != "" {
				return eqForm(a)
			}
			return []string{"--" + a.f.Name, a.value}
		}
		altForm := func(a argvAssign) []string {
			v := a.value
			if a.alt != "" {
				v = a.alt
			}
			if a.f.NoOptDefVal != "" {
				if a.value == "" && a.alt != "" {
					return []string{"--" + a.f.Name + "=" + a.alt}
				}
				return eqForm(a)
			}
			if a.f.Shorthand != "" {
				if v != "" && !strings.HasPrefix(v, "=") && seed%2 == 0 {
					return []string{"-" + a.f.Shorthand + v}
				}
				return []string{"-" + a.f.Shorthand, v}
			}
			return []string{"--" + a.f.Name + "=" + v}
		}

		build := func(form func(argvAssign) []string, order []int, posFirst, rootFirst bool) []string {
			argv := []string{}
			var pre, post []string
			for _, i := range order {
				a := assigns[i]
				if rootFirst && a.rootPersis {
					pre = append(pre, form(a)...)
				} else {
					post = append(post, form(a)...)
				}
			}
			argv = append(argv, pre...)
			argv = append(argv, leaf.path...)
			if posFirst {
				argv = append(argv, pos...)
				argv = append(argv, post...)
				return argv
			}
			argv = append(argv, post...)
			if dashPos {
				argv = append(argv, "--")
			}
			return append(argv, pos...)
		}

		order := make([]int, len(assigns))
		for i := range order {
			order[i] = i
		}
		shuffled := slices.Clone(order)
		rng := rand.New(rand.NewPCG(seed, seed>>1))
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

		renderings := map[string][]string{
			"eq":        build(eqForm, order, false, false),
			"space":     build(spaceForm, order, false, false),
			"alt":       build(altForm, shuffled, false, false),
			"rootFirst": build(eqForm, order, false, true),
		}
		if !dashPos {
			renderings["posFirst"] = build(eqForm, order, true, false)
			withDash := build(eqForm, order, false, false)
			withDash = append(withDash[:len(withDash)-len(pos)], append([]string{"--"}, pos...)...)
			renderings["dashdash"] = withDash
		}

		base, _ := runArgv(renderings["eq"])
		for name, argv := range renderings {
			got, _ := runArgv(argv)
			if !argvSame(base, got) {
				t.Fatalf("argv metamorphic: eq %q -> %+v\n%s %q -> %+v", renderings["eq"], base, name, argv, got)
			}
		}
		if !base.err && base.path != "" && !slices.Equal(base.args, pos) && !(len(pos) == 0 && len(base.args) == 0) {
			t.Fatalf("positionals: %q parsed args %q, want %q", renderings["eq"], base.args, pos)
		}

		if secret {
			var sf *pflag.Flag
			for _, fl := range cands {
				if fl.Value.Type() == "string" || fl.Value.Type() == "stringArray" {
					sf = fl
					break
				}
			}
			if sf == nil {
				return
			}
			argv := append(slices.Clone(leaf.path), "--"+sf.Name+"="+argvSentinel, "--dsdfz-no-such-flag")
			res, output := runArgv(argv)
			if !res.err {
				t.Fatalf("premise: unknown flag accepted: %q", argv)
			}
			if strings.Contains(output, argvSentinel) {
				t.Fatalf("secret echo: unrelated flag value echoed on parse error %q:\n%s", argv, output)
			}
		}
	})
}

func argvSame(a, b argvResult) bool {
	if a.err || b.err {
		return a.err == b.err
	}
	if a.path != b.path || !slices.Equal(a.args, b.args) || len(a.flags) != len(b.flags) {
		return false
	}
	for k, v := range a.flags {
		if b.flags[k] != v {
			return false
		}
	}
	return true
}
