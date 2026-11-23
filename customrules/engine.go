// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package customrules

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/issue"
)

// compiledAnchor is the runtime form of AnchorConfig with the regular
// expression pre-compiled.
type compiledAnchor struct {
	config      AnchorConfig
	pattern     *regexp.Regexp
	argPosition int
	hasArgPos   bool
}

// compiledExclude is the runtime form of ExcludeConfig.
type compiledExclude struct {
	config     ExcludeConfig
	wrapperSet map[string]bool
	valueSet   map[string]bool
}

// declarativeRule evaluates one RuleConfig. A fresh instance is built for every
// package walk through the RuleBuilder, so the per-package state needs no
// locking; runtime counters are merged into the process-wide stats registry.
type declarativeRule struct {
	meta     issue.MetaData
	cwe      string
	anchors  []compiledAnchor
	excludes []compiledExclude
	stats    *RuleStats

	// regexDisabled flips to true after the first timeout. The rule then skips
	// every regular expression anchor for the rest of this package walk.
	regexDisabled      bool
	warnedUnclassified bool

	// Per-file state, reset when entering a new *ast.File.
	currentFile      *ast.File
	argValueCache    map[*ast.CallExpr]map[int]string
	wrapperIndex     map[string]*ast.FuncDecl
	wrapperIndexDone bool
}

// registered node types: call anchors and string anchors visit calls and
// literals, struct tags are inspected on type declarations, and the file node
// is used for per-file anchor-miss bookkeeping.
var triggerNodes = []ast.Node{
	(*ast.File)(nil),
	(*ast.CallExpr)(nil),
	(*ast.BasicLit)(nil),
	(*ast.TypeSpec)(nil),
}

// Builder turns validated RuleConfig values into gosec rule builders ready to
// be merged with the built-in rule list.
func Builder(configs []RuleConfig) (map[string]gosec.RuleBuilder, error) {
	builders := make(map[string]gosec.RuleBuilder, len(configs))
	for _, cfg := range configs {
		if _, err := newDeclarativeRule(cfg); err != nil {
			return nil, err
		}
		builders[cfg.ID] = func(id string, _ gosec.Config) (gosec.Rule, []ast.Node) {
			// Re-instantiate per package walk so per-package state stays local
			// to the goroutine performing the walk.
			fresh, err := newDeclarativeRule(cfg)
			if err != nil {
				// Validation already compiled every pattern; this cannot fail.
				panic(err)
			}
			return fresh, triggerNodes
		}
	}
	return builders, nil
}

func newDeclarativeRule(cfg RuleConfig) (*declarativeRule, error) {
	severity, err := parseScore(cfg.Severity)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", cfg.ID, err)
	}
	confidence, err := parseScore(cfg.Confidence)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", cfg.ID, err)
	}

	anchors := make([]compiledAnchor, 0, len(cfg.Anchors))
	for _, anchor := range cfg.Anchors {
		compiled := compiledAnchor{
			config:      anchor,
			argPosition: 0,
			hasArgPos:   anchor.ArgPosition != nil,
		}
		if anchor.ArgPosition != nil {
			compiled.argPosition = *anchor.ArgPosition
		}
		if anchor.Pattern != "" {
			re, err := regexp.Compile(anchor.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %s: invalid pattern: %w", cfg.ID, err)
			}
			compiled.pattern = re
		}
		anchors = append(anchors, compiled)
	}

	excludes := make([]compiledExclude, 0, len(cfg.Excludes))
	for _, exclude := range cfg.Excludes {
		compiled := compiledExclude{config: exclude}
		if exclude.Kind == ExcludeWrapper {
			compiled.wrapperSet = make(map[string]bool, len(exclude.Wrappers))
			for _, wrapper := range exclude.Wrappers {
				compiled.wrapperSet[wrapper] = true
			}
		}
		if exclude.Kind == ExcludeArgValue {
			compiled.valueSet = make(map[string]bool, len(exclude.Values))
			for _, value := range exclude.Values {
				compiled.valueSet[value] = true
			}
		}
		excludes = append(excludes, compiled)
	}

	return &declarativeRule{
		meta:     issue.NewMetaData(cfg.ID, cfg.Description, severity, confidence),
		cwe:      cfg.CWE,
		anchors:  anchors,
		excludes: excludes,
		stats:    registerStats(cfg.ID),
	}, nil
}

func parseScore(value string) (issue.Score, error) {
	switch strings.ToLower(value) {
	case "low":
		return issue.Low, nil
	case "medium":
		return issue.Medium, nil
	case "high":
		return issue.High, nil
	default:
		return issue.Low, fmt.Errorf("invalid score %q", value)
	}
}

// ID satisfies the gosec.Rule interface.
func (r *declarativeRule) ID() string {
	return r.meta.ID()
}

// Match evaluates every anchor against the visited node.
func (r *declarativeRule) Match(n ast.Node, ctx *gosec.Context) (*issue.Issue, error) {
	switch node := n.(type) {
	case *ast.File:
		r.enterFile(node)
		return nil, nil
	case *ast.CallExpr:
		return r.matchCall(node, ctx), nil
	case *ast.BasicLit:
		return r.matchStringLiteral(node, ctx), nil
	case *ast.TypeSpec:
		return r.matchTypeSpec(node, ctx), nil
	}
	return nil, nil
}

// enterFile resets the per-file bookkeeping and records anchor misses. An
// anchor whose referenced package or type is absent from a file can never
// match there, so it is counted as a miss up front; the scan itself is never
// interrupted.
func (r *declarativeRule) enterFile(file *ast.File) {
	if r.currentFile == file {
		return
	}
	r.currentFile = file
	r.argValueCache = make(map[*ast.CallExpr]map[int]string)
	r.wrapperIndex = nil
	r.wrapperIndexDone = false

	for _, anchor := range r.anchors {
		if r.anchorAbsentFromFile(file, anchor) {
			r.stats.addAnchorMiss()
		}
	}
}

// anchorAbsentFromFile decides whether an anchor's referenced symbol is simply
// absent from the file (a miss) rather than present but not matching.
func (r *declarativeRule) anchorAbsentFromFile(file *ast.File, anchor compiledAnchor) bool {
	switch anchor.config.Kind {
	case AnchorPackageCall:
		return !fileImportsPackage(file, anchor.config.Package)
	case AnchorMethodCall:
		// Present only when a selector call with the method name exists. When
		// no such call exists the receiver type is effectively absent.
		return !fileUsesMethodName(file, anchor.config.Method)
	default:
		// Regex anchors evaluate actual literals/tags; non-matching text is a
		// normal non-match, not a missing symbol.
		return false
	}
}

func fileImportsPackage(file *ast.File, pkgPath string) bool {
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		if path == pkgPath {
			return true
		}
	}
	return false
}

// fileUsesMethodName reports whether the file contains any selector call
// whose method name equals the anchor's method.
func fileUsesMethodName(file *ast.File, method string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == method {
			found = true
			return false
		}
		return true
	})
	return found
}

func (r *declarativeRule) matchCall(call *ast.CallExpr, ctx *gosec.Context) *issue.Issue {
	for _, anchor := range r.anchors {
		if anchor.config.Kind != AnchorPackageCall && anchor.config.Kind != AnchorMethodCall {
			continue
		}
		if !r.callMatchesAnchor(call, anchor, ctx) {
			continue
		}
		if anchor.hasArgPos && !r.argumentUntrusted(call, anchor.argPosition, ctx) {
			continue
		}
		if r.isExcluded(call, ctx) {
			continue
		}
		return r.newIssue(call, ctx)
	}
	return nil
}

func (r *declarativeRule) callMatchesAnchor(call *ast.CallExpr, anchor compiledAnchor, ctx *gosec.Context) bool {
	selector, ident, err := gosec.GetCallInfo(call, ctx)
	if err != nil {
		return false
	}
	switch anchor.config.Kind {
	case AnchorPackageCall:
		// GetCallInfo returns the local package name for package-level calls;
		// resolve it through the import tracker so aliases are handled.
		if strings.ContainsRune(selector, '.') {
			return false
		}
		path, ok := gosec.GetImportPath(selector, ctx)
		if !ok {
			return false
		}
		return path == anchor.config.Package && ident == anchor.config.Function
	case AnchorMethodCall:
		return receiverTypeMatches(selector, anchor.config.ReceiverType) && ident == anchor.config.Method
	}
	return false
}

// receiverTypeMatches compares the type string produced by the type checker
// (e.g. "*os.File", "os/exec.Cmd") with the configured receiver type. A
// configured pointer type also matches the bare value type.
func receiverTypeMatches(actual, configured string) bool {
	if actual == configured {
		return true
	}
	if strings.HasPrefix(configured, "*") {
		return actual == strings.TrimPrefix(configured, "*")
	}
	return false
}

// argumentUntrusted reports whether the argument at position is derived from
// a non-constant source. Statically resolvable constants, literals and const
// identifiers are trusted; everything else (function parameters, returns,
// os.Getenv, etc.) is untrusted. A position past the end of the argument list
// can never be observed, so it does not match.
func (r *declarativeRule) argumentUntrusted(call *ast.CallExpr, position int, ctx *gosec.Context) bool {
	if position < 0 || position >= len(call.Args) {
		return false
	}
	return !gosec.TryResolve(call.Args[position], ctx)
}

func (r *declarativeRule) matchStringLiteral(lit *ast.BasicLit, ctx *gosec.Context) *issue.Issue {
	if lit.Kind != token.STRING || r.regexDisabled {
		return nil
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return nil
	}
	for _, anchor := range r.anchors {
		if anchor.config.Kind != AnchorStringLiteral {
			continue
		}
		matched, timedOut := matchRegexWithTimeout(context.Background(), anchor.pattern, value)
		if timedOut {
			r.handleTimeout(anchor)
			return nil
		}
		if !matched {
			continue
		}
		return r.newIssue(lit, ctx)
	}
	return nil
}

// matchTypeSpec inspects the struct tags of a named struct type declaration.
func (r *declarativeRule) matchTypeSpec(spec *ast.TypeSpec, ctx *gosec.Context) *issue.Issue {
	if r.regexDisabled {
		return nil
	}
	structType, ok := spec.Type.(*ast.StructType)
	if !ok || structType.Fields == nil {
		return nil
	}
	for _, field := range structType.Fields.List {
		if field.Tag == nil {
			continue
		}
		rawTag, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			continue
		}
		tag := reflect.StructTag(rawTag)
		for _, anchor := range r.anchors {
			if anchor.config.Kind != AnchorStructTag {
				continue
			}
			for _, candidate := range tagCandidates(tag, anchor.config.TagKey) {
				matched, timedOut := matchRegexWithTimeout(context.Background(), anchor.pattern, candidate)
				if timedOut {
					r.handleTimeout(anchor)
					return nil
				}
				if !matched {
					continue
				}
				return r.newIssue(field.Tag, ctx)
			}
		}
	}
	return nil
}

// tagCandidates returns the tag values to inspect: only the value of the
// configured key when set, otherwise every key/value pair carried by the tag.
func tagCandidates(tag reflect.StructTag, key string) []string {
	if key != "" {
		value, ok := tag.Lookup(key)
		if !ok {
			return nil
		}
		return []string{value}
	}
	var values []string
	for _, part := range strings.Split(string(tag), " ") {
		segments := strings.SplitN(part, ":", 2)
		if len(segments) != 2 {
			continue
		}
		value, err := strconv.Unquote(segments[1])
		if err != nil {
			continue
		}
		values = append(values, value)
	}
	return values
}

func (r *declarativeRule) handleTimeout(anchor compiledAnchor) {
	if !r.regexDisabled {
		r.regexDisabled = true
		r.stats.addRegexTimeout()
		logf("custom rule %s: regular expression %q exceeded the time budget and was skipped for this run",
			r.ID(), anchor.config.Pattern)
	}
}

// isExcluded evaluates every configured exclusion against the call.
func (r *declarativeRule) isExcluded(call *ast.CallExpr, ctx *gosec.Context) bool {
	for _, exclude := range r.excludes {
		switch exclude.config.Kind {
		case ExcludeArgValue:
			if r.matchesArgValueExclusion(call, exclude) {
				return true
			}
		case ExcludeWrapper:
			if r.matchesWrapperExclusion(call, ctx, exclude) {
				return true
			}
		}
	}
	return false
}

func (r *declarativeRule) matchesArgValueExclusion(call *ast.CallExpr, exclude compiledExclude) bool {
	position := exclude.config.ArgPosition
	if position < 0 || position >= len(call.Args) {
		return false
	}
	values, ok := r.argValueCache[call]
	if !ok {
		values = make(map[int]string)
		r.argValueCache[call] = values
	}
	value, resolved := values[position]
	if !resolved {
		value, resolved = literalStringValue(call.Args[position])
		if resolved {
			values[position] = value
		}
	}
	return resolved && exclude.valueSet[value]
}

// literalStringValue resolves an argument to its literal string value when it
// is a string literal or a constant identifier holding one.
func literalStringValue(expr ast.Expr) (string, bool) {
	switch node := expr.(type) {
	case *ast.BasicLit:
		if node.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(node.Value)
		if err != nil {
			return "", false
		}
		return value, true
	case *ast.Ident:
		for _, value := range gosec.GetIdentStringValues(node) {
			return value, true
		}
	}
	return "", false
}

func (r *declarativeRule) matchesWrapperExclusion(call *ast.CallExpr, ctx *gosec.Context, exclude compiledExclude) bool {
	enclosing := r.enclosingFunction(call)
	if enclosing == nil {
		return false
	}
	// Match both the local function name and its package-qualified form so a
	// rule can name "safeExec" or "main.safeExec" interchangeably.
	localName := enclosing.Name.Name
	if exclude.wrapperSet[localName] {
		return true
	}
	if ctx.Pkg != nil && exclude.wrapperSet[ctx.Pkg.Name()+"."+localName] {
		return true
	}
	return false
}

// enclosingFunction returns the FuncDecl whose body contains the call. The
// index is built lazily once per file.
func (r *declarativeRule) enclosingFunction(call *ast.CallExpr) *ast.FuncDecl {
	if !r.wrapperIndexDone {
		r.wrapperIndex = make(map[string]*ast.FuncDecl)
		if r.currentFile != nil {
			for _, decl := range r.currentFile.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					r.wrapperIndex[fn.Name.Name] = fn
				}
			}
		}
		r.wrapperIndexDone = true
	}
	for _, fn := range r.wrapperIndex {
		if call.Pos() >= fn.Pos() && call.End() <= fn.End() {
			return fn
		}
	}
	return nil
}

func (r *declarativeRule) newIssue(node ast.Node, ctx *gosec.Context) *issue.Issue {
	if r.cwe == "" && !r.warnedUnclassified {
		r.warnedUnclassified = true
		r.stats.addUnclassified()
		logf("custom rule %s: no CWE mapping configured, reporting as unclassified", r.ID())
	}
	found := ctx.NewIssue(node, r.ID(), r.meta.What, r.meta.Severity, r.meta.Confidence)
	if found.Cwe == nil {
		// Built-in rules keep their nil-when-unmapped behaviour; declarative
		// rules always carry the unclassified placeholder so every report
		// stays structurally complete.
		found.Cwe = issue.ResolveCWE(r.ID())
	}
	return found
}

// RuleTriggerNodes exposes the AST node types declarative rules register for.
func RuleTriggerNodes() []ast.Node {
	return triggerNodes
}
