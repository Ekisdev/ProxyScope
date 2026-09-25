package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// compiled is a Rule with every regex it uses pre-compiled and a few
// derived facts cached, so matching a request/response never compiles a
// regex or re-parses the scope. Built once per Load/Save by compile.
type compiled struct {
	rule Rule

	hostWildcard bool   // Scope.Host starts with "*."
	hostMatch    string // lowercase host (wildcard suffix without "*") to compare against

	pathRegex *regexp.Regexp // set when Scope.PathMatch == PathRegex

	conditions []compiledCondition
	action     compiledAction

	needsBody bool // a condition or the action inspects/replaces the body
}

type compiledCondition struct {
	c  Condition
	re *regexp.Regexp // set when c.Match == MatchRegex
}

type compiledAction struct {
	a  Action
	re *regexp.Regexp // set when a.Type == ActionBodyRegexReplace
}

// compiledSet is the active rule set, swapped atomically by Engine on every
// successful load/save so concurrent requests never see a half-updated set.
type compiledSet struct {
	rules         []compiled
	needsReqBody  bool
	needsRespBody bool
}

// compile validates f and produces the compiled set to run, or a readable
// error naming the offending rule. It never panics on malformed input.
func compile(f File) (*compiledSet, error) {
	if f.Version == 0 {
		f.Version = 1 // tolerate a hand-written file that omits version
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported rules file version %d (expected 1)", f.Version)
	}
	seen := map[string]bool{}
	set := &compiledSet{rules: make([]compiled, 0, len(f.Rules))}
	for i, r := range f.Rules {
		if r.ID == "" {
			return nil, ruleError(i, "", "id is required")
		}
		if !isRuleID(r.ID) {
			return nil, ruleError(i, r.ID, "id %q must contain only letters, digits, '-', '_' or '.'", r.ID)
		}
		if seen[r.ID] {
			return nil, ruleError(i, r.ID, "duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true

		c, err := compileRule(r)
		if err != nil {
			return nil, ruleError(i, r.ID, "%v", err)
		}
		set.rules = append(set.rules, c)
		if r.Enabled && c.needsBody {
			if r.Direction == DirectionRequest {
				set.needsReqBody = true
			} else {
				set.needsRespBody = true
			}
		}
	}
	return set, nil
}

func compileRule(r Rule) (compiled, error) {
	c := compiled{rule: r}
	switch r.Direction {
	case DirectionRequest, DirectionResponse:
	default:
		return c, fmt.Errorf("direction must be %q or %q, got %q", DirectionRequest, DirectionResponse, r.Direction)
	}

	host := strings.ToLower(strings.TrimSpace(r.Scope.Host))
	if strings.HasPrefix(host, "*.") {
		c.hostWildcard = true
		c.hostMatch = host[1:] // keep the leading '.', e.g. ".example.com"
	} else {
		c.hostMatch = host
	}

	pathMatch := r.Scope.PathMatch
	if pathMatch == "" {
		pathMatch = PathExact
	}
	switch pathMatch {
	case PathExact, PathPrefix:
	case PathRegex:
		re, err := regexp.Compile(r.Scope.Path)
		if err != nil {
			return c, fmt.Errorf("scope.path: invalid regex: %w", err)
		}
		c.pathRegex = re
	default:
		return c, fmt.Errorf("scope.path_match must be %q, %q or %q, got %q", PathExact, PathPrefix, PathRegex, pathMatch)
	}
	c.rule.Scope.PathMatch = pathMatch

	var statusEquals []int
	headerExact := map[string]string{}
	for i, cond := range r.Conditions {
		cc, err := compileCondition(r.Direction, cond)
		if err != nil {
			return c, fmt.Errorf("condition #%d: %w", i+1, err)
		}
		if cond.Type == ConditionStatus {
			statusEquals = append(statusEquals, *cond.Equals)
		}
		if cond.Type == ConditionHeader && cond.Match == MatchExact {
			key := strings.ToLower(cond.Name)
			if prev, ok := headerExact[key]; ok && prev != cond.Value {
				return c, fmt.Errorf("condition #%d: header %q can never equal both %q and %q at once", i+1, cond.Name, prev, cond.Value)
			}
			headerExact[key] = cond.Value
		}
		if cc.c.Type == ConditionBody {
			c.needsBody = true
		}
		c.conditions = append(c.conditions, cc)
	}
	for i := 1; i < len(statusEquals); i++ {
		if statusEquals[i] != statusEquals[0] {
			return c, fmt.Errorf("conditions require the status to equal both %d and %d at once, which is impossible", statusEquals[0], statusEquals[i])
		}
	}

	ca, err := compileAction(r.Direction, r.Action)
	if err != nil {
		return c, fmt.Errorf("action: %w", err)
	}
	if r.Action.Type == ActionReplaceBody || r.Action.Type == ActionBodyRegexReplace {
		c.needsBody = true
	}
	c.action = ca
	return c, nil
}

func compileCondition(dir Direction, cond Condition) (compiledCondition, error) {
	cc := compiledCondition{c: cond}
	switch cond.Type {
	case ConditionHeader:
		if cond.Name == "" {
			return cc, fmt.Errorf("header condition needs name")
		}
		if !isHeaderToken(cond.Name) {
			return cc, fmt.Errorf("header condition: %q is not a valid header name", cond.Name)
		}
		switch cond.Match {
		case MatchExact, MatchContains:
		case MatchRegex:
			re, err := regexp.Compile(cond.Value)
			if err != nil {
				return cc, fmt.Errorf("header condition: invalid regex: %w", err)
			}
			cc.re = re
		default:
			return cc, fmt.Errorf("header condition: match must be %q, %q or %q, got %q", MatchExact, MatchContains, MatchRegex, cond.Match)
		}
	case ConditionBody:
		switch cond.Match {
		case MatchContains:
		case MatchRegex:
			re, err := regexp.Compile(cond.Value)
			if err != nil {
				return cc, fmt.Errorf("body condition: invalid regex: %w", err)
			}
			cc.re = re
		default:
			return cc, fmt.Errorf("body condition: match must be %q or %q, got %q", MatchContains, MatchRegex, cond.Match)
		}
	case ConditionStatus:
		if dir != DirectionResponse {
			return cc, fmt.Errorf("status condition only applies to response-direction rules")
		}
		if cond.Equals == nil {
			return cc, fmt.Errorf("status condition needs equals")
		}
		if *cond.Equals < 100 || *cond.Equals > 599 {
			return cc, fmt.Errorf("status condition: equals must be a valid HTTP status (100-599), got %d", *cond.Equals)
		}
	default:
		return cc, fmt.Errorf("type must be %q, %q or %q, got %q", ConditionHeader, ConditionBody, ConditionStatus, cond.Type)
	}
	return cc, nil
}

func compileAction(dir Direction, a Action) (compiledAction, error) {
	ca := compiledAction{a: a}
	switch a.Type {
	case ActionReplaceHeader, ActionAddHeader:
		if a.Name == "" {
			return ca, fmt.Errorf("%s needs name", a.Type)
		}
		if !isHeaderToken(a.Name) {
			return ca, fmt.Errorf("%s: %q is not a valid header name", a.Type, a.Name)
		}
		if strings.ContainsAny(a.Value, "\x00\r\n") {
			return ca, fmt.Errorf("%s: value contains invalid characters", a.Type)
		}
	case ActionRemoveHeader:
		if a.Name == "" {
			return ca, fmt.Errorf("remove_header needs name")
		}
		if !isHeaderToken(a.Name) {
			return ca, fmt.Errorf("remove_header: %q is not a valid header name", a.Name)
		}
	case ActionReplaceBody:
		// Body may legitimately be empty (replace with an empty body).
	case ActionBodyRegexReplace:
		re, err := regexp.Compile(a.Pattern)
		if err != nil {
			return ca, fmt.Errorf("body_regex_replace: invalid pattern: %w", err)
		}
		if err := checkReplacementRefs(re, a.Replacement); err != nil {
			return ca, fmt.Errorf("body_regex_replace: %w", err)
		}
		ca.re = re
	case ActionSetStatus:
		if dir != DirectionResponse {
			return ca, fmt.Errorf("set_status only applies to response-direction rules")
		}
		if a.Status < 100 || a.Status > 599 {
			return ca, fmt.Errorf("set_status: status must be a valid HTTP status (100-599), got %d", a.Status)
		}
	default:
		return ca, fmt.Errorf("type must be one of %q, %q, %q, %q, %q, %q, got %q",
			ActionReplaceHeader, ActionAddHeader, ActionRemoveHeader, ActionReplaceBody, ActionBodyRegexReplace, ActionSetStatus, a.Type)
	}
	return ca, nil
}

// checkReplacementRefs reports an error if replacement references a capture
// group ($1, ${name}, ...) that pattern does not actually have, so a typo'd
// group number fails loudly at load time instead of silently expanding to
// nothing at request time (Go's regexp.Expand semantics).
func checkReplacementRefs(pattern *regexp.Regexp, replacement string) error {
	names := pattern.SubexpNames()
	byName := map[string]bool{}
	for _, n := range names {
		if n != "" {
			byName[n] = true
		}
	}
	numGroups := pattern.NumSubexp()
	for _, ref := range referencedGroups(replacement) {
		if n, err := strconv.Atoi(ref); err == nil {
			if n < 0 || n > numGroups {
				return fmt.Errorf("replacement references capture group $%s, but the pattern only has %d group(s)", ref, numGroups)
			}
			continue
		}
		if !byName[ref] {
			return fmt.Errorf("replacement references named capture group %q, which the pattern does not define", ref)
		}
	}
	return nil
}

// referencedGroups extracts the $name/${name} tokens from a Go
// regexp.Expand-style replacement template ("$$" is a literal dollar, not a
// reference).
func referencedGroups(s string) []string {
	var refs []string
	i := 0
	for i < len(s) {
		if s[i] != '$' {
			i++
			continue
		}
		i++ // consume '$'
		switch {
		case i >= len(s):
			// trailing lone '$': nothing to reference.
		case s[i] == '$':
			i++ // "$$" is a literal dollar
		case s[i] == '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				i = len(s)
				break
			}
			refs = append(refs, s[i+1:i+end])
			i += end + 1
		default:
			start := i
			for i < len(s) && isWordByte(s[i]) {
				i++
			}
			if i > start {
				refs = append(refs, s[start:i])
			}
		}
	}
	return refs
}

func isWordByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_'
}

// isRuleID reports whether s is a safe, stable rule identifier.
func isRuleID(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// isHeaderToken reports whether s is a valid HTTP header name (RFC 9110 token).
func isHeaderToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}
