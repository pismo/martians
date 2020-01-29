package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/martian/v3"
	"github.com/google/martian/v3/log"
	"github.com/google/martian/v3/parse"
	"github.com/google/martian/v3/proxyutil"
	"gopkg.in/square/go-jose.v2/jwt"
)

func init() {
	parse.Register("jwt.Modifier", jwtClaimModifierFromJSON)
}

type jwtClaimModifier struct {
	claim, header string
}

// jwtClaimModifierJSON to Unmarshal the JSON configuration
type jwtClaimModifierJSON struct {
	Claim  string               `json:"claim"`
	Header string               `json:"header"`
	Scope  []parse.ModifierType `json:"scope"`
}

// ModifyRequest modifies the header of the request with the given JWT claim.
// This is not an Authentication filter, it does not validates any of the data,
// tokens, signatures, or anything. Only propagates context from the token,
// withou verifying it.
func (m *jwtClaimModifier) ModifyRequest(req *http.Request) error {
	log.Debugf("header: jwtClaimModifier.ModifyRequest %s, claim: %s, header: %s", req.URL, m.claim, m.header)

	h := proxyutil.RequestHeader(req)

	header := h.Get("Authorization")

	claims, err := parseAuthorization(header)

	if err != nil {
		log.Debugf("header: jwtClaimModifier.ModifyRequest %s, error: %v", req.URL, err.Error())
		return nil
	}

	h.Set(m.header, fmt.Sprintf("%v", claims[m.claim]))

	return nil
}

func parseAuthorization(header string) (claims map[string]interface{}, err error) {

	splitHeader := strings.Split(header, "Bearer")

	if len(splitHeader) != 2 {
		return nil, fmt.Errorf("Not a bearer token in Authorization header")
	}

	tokenBase64 := splitHeader[1]

	token, err := jwt.ParseSigned(tokenBase64)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse JWT: %v", err.Error())
	}

	c := make(map[string]interface{})
	// Signature validation should be done in an earlier phase of the request.
	err = token.UnsafeClaimsWithoutVerification(&c)

	if err != nil {
		return nil, fmt.Errorf("Failed to parse JWT claims: %v", err.Error())
	}

	return c, nil
}

// NewJwtClaimModifier returns a request modifier that will set the configured
// header to the value of the configured JWT claim
func NewJwtClaimModifier(claim, header string) martian.RequestModifier {
	return &jwtClaimModifier{
		claim:  claim,
		header: header,
	}
}

// jwtClaimModifierFromJSON takes a JSON message as a byte slice and returns
// a header.modifier and an error.
//
// Example JSON:
// {
//   "header.JwtClaim": {
//		 "scope": ["request"],
//     "claim": "account_id",
//     "header": "x-account-id"
//   }
// }
func jwtClaimModifierFromJSON(b []byte) (*parse.Result, error) {
	msg := &jwtClaimModifierJSON{}

	if err := json.Unmarshal(b, msg); err != nil {
		return nil, err
	}

	return parse.NewResult(NewJwtClaimModifier(msg.Claim, msg.Header), msg.Scope)
}
