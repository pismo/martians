package jwt

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/martian/log"
	"github.com/google/martian/proxyutil"
)

// Matcher is a conditonal evalutor of request or
// response claims to be used in structs that take conditions.
type Matcher struct {
	claim    string
	resource string
}

// NewMatcher builds a jwt uri matcher.
func NewMatcher(claim, resource string) *Matcher {
	return &Matcher{
		claim:    claim,
		resource: resource,
	}
}

// MatchRequest evaluates a request and returns whether or not
// the request uri matches the jwt claim
func (m *Matcher) MatchRequest(req *http.Request) bool {
	log.Debugf("header: jwt.Filter%s, claim: %s, resource: %s", req.URL, m.claim, m.resource)

	h := proxyutil.RequestHeader(req)

	header := h.Get("Authorization")

	claims, err := parseAuthorization(header)

	if err != nil {
		log.Debugf("jwt parsing failed: %s", err.Error())
		return false
	}

	err = match(m.resource, fmt.Sprintf("%v", claims[m.claim]), req.URL.String())

	if err != nil {
		log.Debugf("jwt claim validation failed: %s", err.Error())
		return false
	}

	return true
}

// MatchResponse evaluates a response and returns whether or not the response
// contains a uri matching the jwt claim.
func (m *Matcher) MatchResponse(res *http.Response) bool {
	return false
}

func match(resource string, value string, rawurl string) error {

	regex := fmt.Sprintf("%s%s", resource, `/([^/\r\n]+)`)

	u, err := url.Parse(rawurl)
	if err != nil {
		return fmt.Errorf("could not parse URI: %s", err.Error())
	}

	if value == "" {
		return fmt.Errorf("missing resource value")
	}

	uri := u.RequestURI()

	// ¯\_(ツ)_/¯
	// Removing the resource if it is the prefix of the URI:
	// `/accounts/v1/accounts/10` becomes `/v1/accounts/10`,
	resourceIndex := strings.HasPrefix(uri, fmt.Sprintf("/%s/v", resource))
	if resourceIndex {
		uri = uri[len(resource):]
	}

	re := regexp.MustCompile(regex)
	for {

		pos := re.FindStringSubmatchIndex(uri)
		if len(pos) < 4 {
			break
		}

		uriValue := string(uri[pos[2]:pos[3]])

		uri = uri[pos[3]:]

		if uriValue != value {
			return fmt.Errorf("resource(%s) id mismatch, uri: %s, jwt claim: %s", resource, uriValue, value)
		}
	}

	return nil
}
