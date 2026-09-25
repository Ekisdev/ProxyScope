package rules

import (
	"net/http"
	"net/url"
	"strings"
)

// target is the pre-parsed information a compiled rule matches against. It
// is built once per direction per request, then kept up to date as each
// matching rule's action mutates the message, so later rules in the same
// pass see the result of earlier ones.
type target struct {
	host   string // lowercase hostname, no port
	path   string // URL path, no query string
	method string
	header http.Header
	body   []byte // meaningful only if bodyAvailable
	status int    // response direction only

	// bodyAvailable is false when the body was never buffered (too large,
	// streaming, or simply not needed by anything). A rule whose condition
	// or action touches the body must not fire in that case: it would
	// either see nothing, or (for a body-replacing action) silently discard
	// the real body the wire still streams to the client untouched.
	bodyAvailable bool
}

// scopeOf extracts the host/path/method a rule's scope is compared against
// from the request that produced (or will produce) the exchange.
func scopeOf(rawURL, method string) (host, path, m string) {
	m = strings.ToUpper(method)
	if u, err := url.Parse(rawURL); err == nil {
		host, path = strings.ToLower(u.Hostname()), u.Path
	}
	return
}

// matches reports whether t satisfies c's scope and every condition (AND).
func (c *compiled) matches(dir Direction, t target) bool {
	if c.rule.Direction != dir || !c.rule.Enabled {
		return false
	}
	if c.needsBody && !t.bodyAvailable {
		return false
	}
	if !c.matchesScope(t) {
		return false
	}
	for _, cond := range c.conditions {
		if !cond.matches(t) {
			return false
		}
	}
	return true
}

func (c *compiled) matchesScope(t target) bool {
	if c.hostMatch != "" {
		switch {
		case c.hostWildcard:
			if t.host != c.hostMatch[1:] && !strings.HasSuffix(t.host, c.hostMatch) {
				return false
			}
		case t.host != c.hostMatch:
			return false
		}
	}
	if c.rule.Scope.Method != "" && !strings.EqualFold(c.rule.Scope.Method, t.method) {
		return false
	}
	if c.rule.Scope.Path == "" {
		return true
	}
	switch c.rule.Scope.PathMatch {
	case PathPrefix:
		return strings.HasPrefix(t.path, c.rule.Scope.Path)
	case PathRegex:
		return c.pathRegex.MatchString(t.path)
	default: // PathExact
		return t.path == c.rule.Scope.Path
	}
}

func (cc compiledCondition) matches(t target) bool {
	switch cc.c.Type {
	case ConditionHeader:
		for _, v := range t.header.Values(cc.c.Name) {
			if textMatches(cc.c.Match, cc.re, cc.c.Value, v) {
				return true
			}
		}
		return false
	case ConditionBody:
		return textMatches(cc.c.Match, cc.re, cc.c.Value, string(t.body))
	case ConditionStatus:
		return t.status == *cc.c.Equals
	default:
		return false
	}
}

func textMatches(mode TextMatch, re interface{ MatchString(string) bool }, want, got string) bool {
	switch mode {
	case MatchExact:
		return got == want
	case MatchContains:
		return strings.Contains(got, want)
	case MatchRegex:
		return re.MatchString(got)
	default:
		return false
	}
}
