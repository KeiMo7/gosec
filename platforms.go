package gosec

import (
	"bufio"
	"errors"
	"fmt"
	"go/build"
	"go/build/constraint"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// Platform identifies a Go build target as a GOOS/GOARCH pair.
type Platform struct {
	GOOS   string
	GOARCH string
}

// String returns the platform in the canonical GOOS/GOARCH form.
func (p Platform) String() string {
	if p.GOARCH == "" {
		return p.GOOS
	}
	return p.GOOS + "/" + p.GOARCH
}

// HostPlatform returns the platform gosec itself is running on.
func HostPlatform() Platform {
	return Platform{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

// knownPlatforms lists the GOOS/GOARCH pairs the Go toolchain can target.
// It mirrors `go tool dist list` and is used to validate configuration and to
// resolve GOOS-only entries to a concrete architecture.
var knownPlatforms = map[string]bool{
	"aix/ppc64":       true,
	"android/386":     true,
	"android/amd64":   true,
	"android/arm":     true,
	"android/arm64":   true,
	"darwin/amd64":    true,
	"darwin/arm64":    true,
	"dragonfly/amd64": true,
	"freebsd/386":     true,
	"freebsd/amd64":   true,
	"freebsd/arm":     true,
	"freebsd/arm64":   true,
	"illumos/amd64":   true,
	"ios/amd64":       true,
	"ios/arm64":       true,
	"js/wasm":         true,
	"linux/386":       true,
	"linux/amd64":     true,
	"linux/arm":       true,
	"linux/arm64":     true,
	"linux/loong64":   true,
	"linux/mips":      true,
	"linux/mips64":    true,
	"linux/mips64le":  true,
	"linux/mipsle":    true,
	"linux/ppc64":     true,
	"linux/ppc64le":   true,
	"linux/riscv64":   true,
	"linux/s390x":     true,
	"netbsd/386":      true,
	"netbsd/amd64":    true,
	"netbsd/arm":      true,
	"netbsd/arm64":    true,
	"openbsd/386":     true,
	"openbsd/amd64":   true,
	"openbsd/arm":     true,
	"openbsd/arm64":   true,
	"openbsd/ppc64":   true,
	"openbsd/riscv64": true,
	"plan9/386":       true,
	"plan9/amd64":     true,
	"plan9/arm":       true,
	"solaris/amd64":   true,
	"wasip1/wasm":     true,
	"windows/386":     true,
	"windows/amd64":   true,
	"windows/arm64":   true,
}

var (
	// knownGOOS and knownGOARCH are derived once from knownPlatforms by
	// initKnownPlatforms.
	knownGOOS   = map[string]bool{}
	knownGOARCH = map[string]bool{}
)

// initKnownPlatforms fills knownGOOS and knownGOARCH from the platform table.
// It is called lazily from the helpers that need it rather than from init.
func initKnownPlatforms() {
	for pair := range knownPlatforms {
		goos, goarch, _ := strings.Cut(pair, "/")
		knownGOOS[goos] = true
		knownGOARCH[goarch] = true
	}
}

// defaultArchForOS resolves a GOOS to the architecture gosec uses when a
// configuration only names the operating system. It prefers the host
// architecture when the pair is supported so that a GOOS-only entry for the
// local OS does not silently drift from the platform gosec is running on.
func defaultArchForOS(goos string) (string, bool) {
	if host := HostPlatform(); host.GOOS == goos && knownPlatforms[host.String()] {
		return host.GOARCH, true
	}
	switch goos {
	case "linux", "darwin", "windows", "freebsd", "netbsd", "openbsd", "dragonfly":
		if knownPlatforms[goos+"/amd64"] {
			return "amd64", true
		}
	case "aix", "illumos", "solaris":
		if knownPlatforms[goos+"/ppc64"] {
			return "ppc64", true
		}
		if knownPlatforms[goos+"/amd64"] {
			return "amd64", true
		}
	case "js", "wasip1":
		return "wasm", true
	case "android", "ios":
		return "arm64", true
	case "plan9":
		return "amd64", true
	}
	return "", false
}

// ParsePlatforms parses a list of platform expressions into a de-duplicated,
// ordered platform set. Each expression is either "goos" or "goos/goarch" and
// is matched case-insensitively. A GOOS-only expression resolves to the host
// architecture when that pair is supported.
func ParsePlatforms(expressions []string) ([]Platform, error) {
	var platforms []Platform
	seen := make(map[string]bool)
	for _, raw := range expressions {
		for _, item := range SplitPlatformList(raw) {
			platform, err := parsePlatform(item)
			if err != nil {
				return nil, err
			}
			key := platform.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			platforms = append(platforms, platform)
		}
	}
	return platforms, nil
}

// SplitPlatformList splits a platform list that may be a plain comma separated
// string or a serialized slice such as "[linux/amd64 darwin/arm64]".
func SplitPlatformList(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
}

func parsePlatform(item string) (Platform, error) {
	normalized := strings.ToLower(strings.TrimSpace(item))
	parts := strings.Split(normalized, "/")
	switch len(parts) {
	case 1:
		goos := parts[0]
		arch, ok := defaultArchForOS(goos)
		if !ok {
			return Platform{}, fmt.Errorf("unsupported platform %q: unknown GOOS %q", item, goos)
		}
		return Platform{GOOS: goos, GOARCH: arch}, nil
	case 2:
		platform := Platform{GOOS: parts[0], GOARCH: parts[1]}
		if !knownPlatforms[platform.String()] {
			return Platform{}, fmt.Errorf("unsupported platform %q: not a GOOS/GOARCH pair supported by the Go toolchain", item)
		}
		return platform, nil
	default:
		return Platform{}, fmt.Errorf("invalid platform %q: expected GOOS or GOOS/GOARCH", item)
	}
}

// PlatformSet is the ordered set of platforms a scan covers.
type PlatformSet []Platform

// Strings renders the set in canonical order.
func (s PlatformSet) Strings() []string {
	out := make([]string, len(s))
	for i, p := range s {
		out[i] = p.String()
	}
	return out
}

// Contains reports whether the set includes the platform.
func (s PlatformSet) Contains(p Platform) bool {
	return slices.Contains(s, p)
}

// SortPlatforms returns a copy sorted by GOOS then GOARCH, giving reports a
// deterministic order independent of configuration order.
func SortPlatforms(platforms []Platform) []Platform {
	out := slices.Clone(platforms)
	slices.SortFunc(out, func(a, b Platform) int {
		if c := strings.Compare(a.GOOS, b.GOOS); c != 0 {
			return c
		}
		return strings.Compare(a.GOARCH, b.GOARCH)
	})
	return out
}

// Configuration keys used to declare the platforms a scan should cover. They
// may appear under the "global" block of the configuration file or at the top
// level.
const (
	// PlatformKey declares an explicit target platform list.
	PlatformKey = "platforms"
	// MaxPlatformsKey caps the number of platforms a single run analyzes.
	MaxPlatformsKey = "platforms-max"
	// InferPlatformsKey controls whether the target set may be inferred from
	// the project's declared support range when none is configured.
	InferPlatformsKey = "infer-platforms"
)

// DefaultMaxPlatforms bounds the platform dimension of a single run. It keeps
// the cost of the extra dimension predictable: a project that supports more
// than a handful of platforms must opt into the extra work explicitly or raise
// the budget.
const DefaultMaxPlatforms = 4

// PlatformSelection records how the target platform set was determined.
type PlatformSelection struct {
	// Platforms is the set that will actually be analyzed.
	Platforms PlatformSet
	// Requested is the set named by the configuration before any budget
	// clipping. It equals Platforms when nothing was clipped.
	Requested PlatformSet
	// Excluded lists requested platforms that were dropped to fit the budget.
	Excluded PlatformSet
	// Source explains where the set came from.
	Source string
	// Message is a human readable note about inference, clipping or
	// degradation. It is empty when the selection was fully explicit and fit
	// the budget.
	Message string
	// MaxPlatforms is the resolved budget for the run.
	MaxPlatforms int
}

// Platform selection sources.
const (
	// PlatformSourceExplicit means the platform list came from configuration.
	PlatformSourceExplicit = "explicit"
	// PlatformSourceInferred means the platform list was derived from the
	// project's declared support range.
	PlatformSourceInferred = "inferred"
	// PlatformSourceHost means setup fell back to the host platform.
	PlatformSourceHost = "host"
)

// SelectPlatforms determines the platform set for a scan. An explicit list
// (CLI first, then configuration) always wins; otherwise the project's
// declared support range is consulted. When neither is usable the host
// platform is used and the fallback is reported in Message rather than
// silently applied.
func SelectPlatforms(config Config, rootDirs []string, explicit []string, maxPlatforms int) (PlatformSelection, error) {
	budget := maxPlatforms
	if budget <= 0 {
		budget = DefaultMaxPlatforms
	}
	if maxPlatforms <= 0 {
		// Only consult the configuration when the caller did not set an
		// explicit budget, so the command line always wins.
		if fromConfig, err := config.GetMaxPlatforms(); err == nil && fromConfig > 0 {
			budget = fromConfig
		}
	}
	if len(explicit) == 0 {
		if fromConfig, err := config.GetPlatforms(); err == nil {
			explicit = fromConfig
		}
	}

	if len(explicit) > 0 {
		requested, err := ParsePlatforms(explicit)
		if err != nil {
			return PlatformSelection{}, err
		}
		if len(requested) == 0 {
			return PlatformSelection{}, errors.New("configured platform list is empty")
		}
		return clipPlatforms(requested, budget, PlatformSourceExplicit, ""), nil
	}

	if config.PlatformInferenceEnabled() {
		if inferred, declared := InferPlatforms(rootDirs); declared {
			// A project with platform-specific files usually still has
			// unconstrained files that build on every target, including the
			// host. Union the declared platforms with the host so the host
			// dimension is never lost.
			inferred = dedupePlatforms(append(inferred, HostPlatform()))
			selection := clipPlatforms(inferred, budget, PlatformSourceInferred, "")
			if selection.Message == "" {
				selection.Message = "target platforms inferred from the project's build constraints: " +
					strings.Join(selection.Platforms.Strings(), ", ")
			}
			return selection, nil
		}
	}

	// A project that declares no platform-specific files has no platform
	// dimension to explore: the host platform is the complete answer, and the
	// result is identical to a single-platform run.
	host := HostPlatform()
	return PlatformSelection{
		Platforms:    PlatformSet{host},
		Requested:    PlatformSet{host},
		Source:       PlatformSourceHost,
		MaxPlatforms: budget,
	}, nil
}

func clipPlatforms(requested []Platform, budget int, source, message string) PlatformSelection {
	ordered := SortPlatforms(requested)
	selection := PlatformSelection{
		Requested:    PlatformSet(ordered),
		Platforms:    PlatformSet(ordered),
		Source:       source,
		Message:      message,
		MaxPlatforms: budget,
	}
	if len(ordered) > budget {
		// Keep the host platform when it is among the candidates so the
		// default run still covers the machine gosec runs on, then fill the
		// remaining budget in canonical order.
		host := HostPlatform()
		kept := make([]Platform, 0, budget)
		if slices.Contains(ordered, host) {
			kept = append(kept, host)
		}
		for _, p := range ordered {
			if len(kept) >= budget {
				break
			}
			if p == host {
				continue
			}
			kept = append(kept, p)
		}
		dropped := make([]Platform, 0, len(ordered)-len(kept))
		for _, p := range ordered {
			if !slices.Contains(kept, p) {
				dropped = append(dropped, p)
			}
		}
		selection.Platforms = PlatformSet(SortPlatforms(kept))
		selection.Excluded = PlatformSet(dropped)
		selection.Message = fmt.Sprintf("platform budget of %d exceeded; dropped %s",
			budget, strings.Join(PlatformSet(dropped).Strings(), ", "))
	}
	return selection
}

// GetPlatforms reads an explicit platform list from the configuration. The
// value may be a string, a []string or a decoded JSON array, and may live at
// the top level or under the "global" block.
func (c Config) GetPlatforms() ([]string, error) {
	value, ok := c.configValue(PlatformKey)
	if !ok {
		return nil, fmt.Errorf("no %s configured", PlatformKey)
	}
	items, err := platformValueStrings(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s configuration: %w", PlatformKey, err)
	}
	return items, nil
}

// GetMaxPlatforms reads the platform budget from the configuration.
func (c Config) GetMaxPlatforms() (int, error) {
	value, ok := c.configValue(MaxPlatformsKey)
	if !ok {
		return 0, fmt.Errorf("no %s configured", MaxPlatformsKey)
	}
	switch v := value.(type) {
	case float64:
		return int(v), nil
	case int:
		return v, nil
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, fmt.Errorf("invalid %s value %q", MaxPlatformsKey, v)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("invalid %s value of type %T", MaxPlatformsKey, value)
	}
}

// PlatformInferenceEnabled reports whether platform inference is allowed. It
// defaults to true and can be turned off with "infer-platforms": "false".
func (c Config) PlatformInferenceEnabled() bool {
	value, ok := c.configValue(InferPlatformsKey)
	if !ok {
		return true
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "false", "disabled", "off", "0", "no":
			return false
		}
	}
	return true
}

// configValue looks a key up at the top level first and then under "global",
// tolerating both the raw decoded JSON form and the normalized globals form.
func (c Config) configValue(key string) (interface{}, bool) {
	if c == nil {
		return nil, false
	}
	if value, ok := c[key]; ok {
		return value, true
	}
	globals, ok := c[Globals]
	if !ok {
		return nil, false
	}
	switch settings := globals.(type) {
	case map[string]interface{}:
		value, ok := settings[key]
		return value, ok
	case map[GlobalOption]string:
		value, ok := settings[GlobalOption(key)]
		return value, ok
	}
	return nil, false
}

func platformValueStrings(value interface{}) ([]string, error) {
	switch v := value.(type) {
	case string:
		return SplitPlatformList(v), nil
	case []string:
		return v, nil
	case []interface{}:
		items := make([]string, 0, len(v))
		for _, item := range v {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("platform entries must be strings, got %T", item)
			}
			items = append(items, text)
		}
		return items, nil
	default:
		return nil, fmt.Errorf("platform list must be a string or array, got %T", value)
	}
}

// InferPlatforms inspects the build constraints of Go files under dirs and
// returns the platforms the project declares it supports. Only positive
// platform mentions count: an unconstrained file or a negated constraint says
// nothing about which targets exist. The second result reports whether the
// project commits to a platform dimension at all; when it is false the caller
// should treat the project as single-platform.
func InferPlatforms(dirs []string) ([]Platform, bool) {
	seen := make(map[Platform]bool)
	scanned := 0
	const maxFiles = 50000
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		root, err := filepath.Abs(dir)
		if err != nil {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.IsDir() {
				name := entry.Name()
				if path != root && (name == "vendor" || name == "node_modules" || strings.HasPrefix(name, ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) != ".go" {
				return nil
			}
			if scanned >= maxFiles {
				return filepath.SkipAll
			}
			scanned++
			for _, platform := range declaredPlatforms(path) {
				seen[platform] = true
			}
			return nil
		})
	}
	platforms := make([]Platform, 0, len(seen))
	for platform := range seen {
		platforms = append(platforms, platform)
	}
	return SortPlatforms(platforms), len(platforms) > 0
}

// declaredPlatforms returns the platforms a single source file is restricted
// to through its file name suffix or its build constraints.
func declaredPlatforms(path string) []Platform {
	name := filepath.Base(path)
	var platforms []Platform

	if suffixPlatforms, suffixKnown := fileSuffixPlatforms(name); len(suffixPlatforms) > 0 {
		platforms = append(platforms, suffixPlatforms...)
	} else if !suffixKnown {
		// The suffix mentions a platform-ish token gosec cannot resolve.
		return nil
	}

	if expr := readBuildConstraint(path); expr != nil {
		platforms = append(platforms, positivePlatformTags(expr)...)
	}
	return dedupePlatforms(platforms)
}

// readBuildConstraint reads the //go:build (or legacy // +build) expression
// from the header of a Go file. It stops at the package clause.
func readBuildConstraint(path string) constraint.Expr {
	f, err := os.Open(path) // #nosec G304 -- scanning user supplied source tree
	if err != nil {
		return nil
	}
	defer f.Close() // #nosec G307

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var expr constraint.Expr
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "package ") {
			break
		}
		if constraint.IsGoBuild(line) {
			if parsed, err := constraint.Parse(line); err == nil {
				expr = parsed
			}
			continue
		}
		if strings.HasPrefix(line, "// +build ") && expr == nil {
			if parsed, err := constraint.Parse(line); err == nil {
				expr = parsed
			}
		}
	}
	return expr
}

// positivePlatformTags collects the GOOS/GOARCH tags that a constraint
// requires, ignoring negations and non-platform tags. An architecture-only tag
// is ignored because it does not name an operating system.
func positivePlatformTags(expr constraint.Expr) []Platform {
	initKnownPlatforms()
	var platforms []Platform
	var walk func(constraint.Expr, bool)
	walk = func(expr constraint.Expr, negated bool) {
		switch e := expr.(type) {
		case *constraint.TagExpr:
			if negated {
				return
			}
			if knownGOOS[e.Tag] {
				if arch, ok := defaultArchForOS(e.Tag); ok {
					platforms = append(platforms, Platform{GOOS: e.Tag, GOARCH: arch})
				}
				return
			}
			if knownGOARCH[e.Tag] {
				return
			}
		case *constraint.NotExpr:
			walk(e.X, true)
		case *constraint.AndExpr:
			walk(e.X, negated)
			walk(e.Y, negated)
		case *constraint.OrExpr:
			walk(e.X, negated)
			walk(e.Y, negated)
		}
	}
	walk(expr, false)
	return dedupePlatforms(platforms)
}

// fileSuffixPlatforms maps the implicit GOOS/GOARCH suffixes of a file name
// to platforms. The second result is false when the suffix names a
// platform-like token that could not be resolved.
func fileSuffixPlatforms(name string) ([]Platform, bool) {
	initKnownPlatforms()
	base := strings.TrimSuffix(name, ".go")
	parts := strings.Split(base, "_")
	if len(parts) < 2 {
		return nil, true
	}
	last := parts[len(parts)-1]
	prev := ""
	if len(parts) >= 3 {
		prev = parts[len(parts)-2]
	}
	if knownGOOS[prev] && knownGOARCH[last] {
		return []Platform{{GOOS: prev, GOARCH: last}}, true
	}
	if knownGOOS[last] {
		arch, ok := defaultArchForOS(last)
		if !ok {
			return nil, false
		}
		return []Platform{{GOOS: last, GOARCH: arch}}, true
	}
	// Unknown last token: it may be an architecture, a custom suffix such as
	// "linux" inside a word, or a plain name. Only GOOS/GOARCH names are
	// treated as platform declarations.
	return nil, !knownGOARCH[last]
}

func dedupePlatforms(platforms []Platform) []Platform {
	if len(platforms) == 0 {
		return nil
	}
	seen := make(map[Platform]bool, len(platforms))
	out := make([]Platform, 0, len(platforms))
	for _, p := range platforms {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return SortPlatforms(out)
}

// buildContextForPlatform returns a build.Context pinned to one platform so
// directory imports see exactly the files that platform compiles.
func buildContextForPlatform(platform Platform, buildTags []string) build.Context {
	ctx := build.Default
	ctx.GOOS = platform.GOOS
	ctx.GOARCH = platform.GOARCH
	ctx.CgoEnabled = false
	ctx.BuildTags = buildTags
	return ctx
}
