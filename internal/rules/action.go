package rules

import "net/http"

// apply performs ca's single transformation, mutating header in place (add,
// replace or remove a value) and returning the body/status to use from now
// on (unchanged for action types that don't touch them).
func (ca compiledAction) apply(header http.Header, body []byte, status int) ([]byte, int) {
	switch ca.a.Type {
	case ActionReplaceHeader:
		header.Set(ca.a.Name, ca.a.Value)
	case ActionAddHeader:
		header.Add(ca.a.Name, ca.a.Value)
	case ActionRemoveHeader:
		header.Del(ca.a.Name)
	case ActionReplaceBody:
		body = []byte(ca.a.Body)
	case ActionBodyRegexReplace:
		body = ca.re.ReplaceAll(body, []byte(ca.a.Replacement))
	case ActionSetStatus:
		status = ca.a.Status
	}
	return body, status
}
