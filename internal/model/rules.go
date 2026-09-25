package model

// Match & replace rule types (Phase 4). They live here, not in
// internal/rules, so ui.Rules and proxy.RuleEngine can reference them
// without ui/proxy importing internal/rules directly — the same reason
// Request/Response/Outcome live here for intercept.

// Direction says whether a rule looks at the request on its way upstream or
// the response on its way back to the client.
type Direction string

const (
	DirectionRequest  Direction = "request"
	DirectionResponse Direction = "response"
)

// PathMatch selects how Scope.Path is compared against the request path.
type PathMatch string

const (
	PathExact  PathMatch = "exact"
	PathPrefix PathMatch = "prefix"
	PathRegex  PathMatch = "regex"
)

// TextMatch selects how a header or body condition's Value is interpreted.
type TextMatch string

const (
	MatchExact    TextMatch = "exact"    // header only
	MatchContains TextMatch = "contains" // header, body
	MatchRegex    TextMatch = "regex"    // header, body
)

// ConditionType says what a Condition inspects.
type ConditionType string

const (
	ConditionHeader ConditionType = "header"
	ConditionBody   ConditionType = "body"
	ConditionStatus ConditionType = "status"
)

// ActionType says what an Action does.
type ActionType string

const (
	ActionReplaceHeader    ActionType = "replace_header"
	ActionAddHeader        ActionType = "add_header"
	ActionRemoveHeader     ActionType = "remove_header"
	ActionReplaceBody      ActionType = "replace_body"
	ActionBodyRegexReplace ActionType = "body_regex_replace"
	ActionSetStatus        ActionType = "set_status"
)

// Scope narrows which requests a rule looks at. Empty Host/Path/Method match
// anything. Host is compared against the request's hostname (no port, so a
// rule scopes the same way regardless of which port is used); a leading
// "*." matches that host and any subdomain of it. Path is compared against
// the URL path only (no query string).
type Scope struct {
	Host      string    `yaml:"host,omitempty" json:"host,omitempty"`
	Path      string    `yaml:"path,omitempty" json:"path,omitempty"`
	PathMatch PathMatch `yaml:"path_match,omitempty" json:"pathMatch,omitempty"` // default: exact
	Method    string    `yaml:"method,omitempty" json:"method,omitempty"`
}

// Condition is one AND-combined test a message must pass for the rule's
// action to run. Which fields apply depends on Type:
//   - header: Name is the header to look at; Match and Value select how.
//   - body: Match ("contains" or "regex") and Value select how.
//   - status: Equals is the exact status code required (response direction only).
type Condition struct {
	Type   ConditionType `yaml:"type" json:"type"`
	Name   string        `yaml:"name,omitempty" json:"name,omitempty"`
	Match  TextMatch     `yaml:"match,omitempty" json:"match,omitempty"`
	Value  string        `yaml:"value,omitempty" json:"value,omitempty"`
	Equals *int          `yaml:"equals,omitempty" json:"equals,omitempty"`
}

// Action is the single transformation a rule applies once its scope and
// conditions match. Which fields apply depends on Type:
//   - replace_header/add_header: Name + Value.
//   - remove_header: Name.
//   - replace_body: Body, used verbatim as the new full body.
//   - body_regex_replace: Pattern is matched against the body; every match is
//     replaced by Replacement, which may reference Pattern's own capture
//     groups as $1/${name} (Go regexp.Expand syntax).
//   - set_status: Status (response direction only).
type Action struct {
	Type        ActionType `yaml:"type" json:"type"`
	Name        string     `yaml:"name,omitempty" json:"name,omitempty"`
	Value       string     `yaml:"value,omitempty" json:"value,omitempty"`
	Body        string     `yaml:"body,omitempty" json:"body,omitempty"`
	Pattern     string     `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Replacement string     `yaml:"replacement,omitempty" json:"replacement,omitempty"`
	Status      int        `yaml:"status,omitempty" json:"status,omitempty"`
}

// Rule is one match & replace rule as authored in the YAML file.
type Rule struct {
	ID         string      `yaml:"id" json:"id"`
	Name       string      `yaml:"name,omitempty" json:"name,omitempty"`
	Enabled    bool        `yaml:"enabled" json:"enabled"`
	Direction  Direction   `yaml:"direction" json:"direction"`
	Scope      Scope       `yaml:"scope,omitempty" json:"scope,omitempty"`
	Conditions []Condition `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Action     Action      `yaml:"action" json:"action"`
}

// RulesFile is the top-level shape of the match & replace YAML rules file.
type RulesFile struct {
	Version int    `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}
