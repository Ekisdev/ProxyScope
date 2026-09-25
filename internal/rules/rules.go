// Package rules implements match & replace: declarative rules, loaded from a
// version-controllable YAML file, that automatically rewrite requests and
// responses as they pass through the two pause points in proxy.forward
// (see internal/intercept's doc comment and CLAUDE.md). Unlike live
// intercept, rules need no human in the loop and run whether or not the
// intercept queue is turned on.
//
// A Rule has a scope (host/path/method/direction), zero or more AND-combined
// conditions, and exactly one action. Rules are evaluated in file order;
// every matching rule for a direction applies in order, each seeing the
// previous one's transformation. Regexes are compiled once, when a rule set
// is loaded or saved, never per request (see Engine).
//
// The rule-definition types (Rule, Scope, Condition, Action, ...) live in
// internal/model, not here, so ui.Rules can reference them without the ui
// package importing this one — the same reason model holds Request/Response
// for intercept. This package re-exports them as aliases so its own code
// (and this package's tests) can keep spelling them unqualified.
package rules

import (
	"fmt"

	"proxyscope/internal/model"
)

type (
	Direction     = model.Direction
	PathMatch     = model.PathMatch
	TextMatch     = model.TextMatch
	ConditionType = model.ConditionType
	ActionType    = model.ActionType
	Scope         = model.Scope
	Condition     = model.Condition
	Action        = model.Action
	Rule          = model.Rule
	File          = model.RulesFile
)

const (
	DirectionRequest  = model.DirectionRequest
	DirectionResponse = model.DirectionResponse

	PathExact  = model.PathExact
	PathPrefix = model.PathPrefix
	PathRegex  = model.PathRegex

	MatchExact    = model.MatchExact
	MatchContains = model.MatchContains
	MatchRegex    = model.MatchRegex

	ConditionHeader = model.ConditionHeader
	ConditionBody   = model.ConditionBody
	ConditionStatus = model.ConditionStatus

	ActionReplaceHeader    = model.ActionReplaceHeader
	ActionAddHeader        = model.ActionAddHeader
	ActionRemoveHeader     = model.ActionRemoveHeader
	ActionReplaceBody      = model.ActionReplaceBody
	ActionBodyRegexReplace = model.ActionBodyRegexReplace
	ActionSetStatus        = model.ActionSetStatus
)

// ruleError reports a problem with one rule, identified so it is readable
// even when many rules share similar shapes.
func ruleError(idx int, id, format string, a ...any) error {
	who := fmt.Sprintf("rule #%d", idx+1)
	if id != "" {
		who = fmt.Sprintf("rule #%d (%q)", idx+1, id)
	}
	return fmt.Errorf("%s: %s", who, fmt.Sprintf(format, a...))
}
