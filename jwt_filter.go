package jwt

import (
	"encoding/json"

	"github.com/google/martian/filter"
	"github.com/google/martian/log"
	"github.com/google/martian/parse"
)

//var noop = martian.Noop("jwt.Filter")

type filterJSON struct {
	Claim        string               `json:"claim"`
	Resource     string               `json:"resource"`
	Modifier     json.RawMessage      `json:"modifier"`
	ElseModifier json.RawMessage      `json:"else"`
	Scope        []parse.ModifierType `json:"scope"`
}

func init() {
	parse.Register("jwt.Filter", filterFromJSON)
}

// NewFilter builds a new cookie filter.
func NewFilter(claim, resource string) *filter.Filter {
	log.Debugf("jwt.Filter: claim: %s, resource: %s", claim, resource)
	f := filter.New()
	m := NewMatcher(claim, resource)

	f.SetRequestCondition(m)
	f.SetResponseCondition(m)

	return f
}

// filterFromJSON builds a jwt.Filter from JSON.
//
// Example JSON:
// {
//   "scope": ["request", "result"],
//   "name": "Martian-Testing",
//   "value": "true",
//   "modifier": { ... },
//   "else": { ... }
// }
func filterFromJSON(b []byte) (*parse.Result, error) {
	msg := &filterJSON{}
	if err := json.Unmarshal(b, msg); err != nil {
		return nil, err
	}

	filter := NewFilter(msg.Claim, msg.Resource)

	m, err := parse.FromJSON(msg.Modifier)
	if err != nil {
		return nil, err
	}

	filter.RequestWhenTrue(m.RequestModifier())
	filter.ResponseWhenTrue(m.ResponseModifier())

	if msg.ElseModifier != nil {
		em, err := parse.FromJSON(msg.ElseModifier)
		if err != nil {
			return nil, err
		}

		filter.RequestWhenFalse(em.RequestModifier())
		filter.ResponseWhenFalse(em.ResponseModifier())
	}

	return parse.NewResult(filter, msg.Scope)
}
