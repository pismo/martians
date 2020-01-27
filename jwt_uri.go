package header

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/martian"
	"github.com/google/martian/parse"
	"github.com/google/martian/v3/log"
	"github.com/google/martian/v3/proxyutil"
	"github.com/google/martian/verify"
)

func init() {
	parse.Register("uri.JwtVerifier", verifierFromJSON)
}

const errFormat = "jwt claim(%s) uri verification failed: got %s"

// Verifier verifies the status codes of all responses.
type Verifier struct {
	claim    string
	resource string
	err      *martian.MultiError
}

type verifierJSON struct {
	Claim    string               `json:"claim"`
	Resource string               `json:"resource"`
	Scope    []parse.ModifierType `json:"scope"`
}

// NewJwtUriVerifier returns a new uri.JwtVerifier for URI.
func NewJwtUriVerifier(claim, resource string) verify.RequestVerifier {
	return &Verifier{
		claim:    claim,
		resource: resource,
		err:      martian.NewMultiError(),
	}
}

// ModifyRequest verifies that the URI resource for all requests
// matches JWT claim.
func (v *Verifier) ModifyRequest(req *http.Request) error {
	log.Debugf("header: jwtClaimModifier.ModifyRequest %s, claim: %s, resource: %s",
		req.URL, v.claim, v.resource)

	h := proxyutil.RequestHeader(req)

	header := h.Get("Authorization")

	claims, err := parseAuthorization(header)

	if err != nil {
		//TODO: set statuscode 401 instead of returning error
		return fmt.Errorf("header: jwtClaimModifier.ModifyRequest %s, error: %v", req.URL, err.Error())
	}

	err = validate(v.resource, fmt.Sprintf("%v", claims[v.claim]), req.URL.String())

	if err != nil {
		log.Debugf("jwt claim validation failed: %s", err.Error())
		v.err.Add(fmt.Errorf(errFormat, claims[v.claim], req.URL))
	}

	return nil
}

func validate(resource string, value string, rawurl string) (err error) {

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

// VerifyResponses returns an error if verification for any
// request failed.
// If an error is returned it will be of type *martian.MultiError.
func (v *Verifier) VerifyRequests() error {
	if v.err.Empty() {
		return nil
	}

	return v.err
}

// ResetResponseVerifications clears all failed response verifications.
func (v *Verifier) ResetRequestVerifications() {
	v.err = martian.NewMultiError()
}

// verifierFromJSON builds a status.Verifier from JSON.
//
// Example JSON:
// {
//   "status.Verifier": {
//     "scope": ["request"],
//     "claim": "user_id" ,
//		 "resource": "accounts"
//   }
// }
func verifierFromJSON(b []byte) (*parse.Result, error) {
	msg := &verifierJSON{}
	if err := json.Unmarshal(b, msg); err != nil {
		return nil, err
	}

	return parse.NewResult(NewJwtUriVerifier(msg.Claim, msg.Resource), msg.Scope)
}
