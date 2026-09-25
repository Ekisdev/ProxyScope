package proxy

import (
	"net/http"
	"strings"
)

// isUpgrade reports whether the request asks for a protocol switch
// (e.g. WebSocket), which is not relayed.
func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}
