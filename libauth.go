package libauth

import (
	"fmt"
	"net/http"
	"strings"

	"git.rootprojects.org/root/keypairs"
	"git.rootprojects.org/root/keypairs/keyfetch"
)

// JWS is keypairs.JWS with added debugging information
type JWS struct {
	keypairs.JWS

	Trusted bool    `json:"trusted"`
	Errors  []error `json:"errors,omitempty"`
}

// VerifyJWT will return a verified InspectableToken if possible, or otherwise as much detail as possible, possibly including an InspectableToken with failed verification.
func VerifyJWT(jwt string, issuers keyfetch.Whitelist, r *http.Request) (*JWS, error) {
	jws := keypairs.JWTToJWS(jwt)
	if nil == jws {
		return nil, fmt.Errorf("Bad Request: malformed Authorization header")
	}

	if err := jws.DecodeComponents(); nil != err {
		return &JWS{
			*jws,
			false,
			[]error{err},
		}, err
	}

	return VerifyJWS(jws, issuers, r)
}

// VerifyJWS takes a fully decoded JWS and will return a verified InspectableToken if possible, or otherwise as much detail as possible, possibly including an InspectableToken with failed verification.
func VerifyJWS(jws *keypairs.JWS, issuers keyfetch.Whitelist, r *http.Request) (*JWS, error) {
	var pub keypairs.PublicKey
	kid, kidOK := jws.Header["kid"].(string)
	iss, issOK := jws.Claims["iss"].(string)

	_, jwkOK := jws.Header["jwk"]
	if jwkOK {
		if !kidOK || 0 == len(kid) {
			//errs = append(errs, "must have either header.kid or header.jwk")
			return nil, fmt.Errorf("Bad Request: missing 'kid' identifier")
		} else if !issOK || 0 == len(iss) {
			//errs = append(errs, "payload.iss must exist to complement header.kid")
			return nil, fmt.Errorf("Bad Request: payload.iss must exist to complement header.kid")
		} else {
			// TODO beware domain fronting, we should set domain statically
			// See https://pkg.go.dev/git.rootprojects.org/root/keypairs@v0.6.2/keyfetch
			// (Caddy does protect against Domain-Fronting by default:
			//     https://github.com/caddyserver/caddy/issues/2500)
			if !issuers.IsTrustedIssuer(iss, r) {
				return nil, fmt.Errorf("Bad Request: 'iss' is not a trusted issuer")
			}
		}
		var err error
		pub, err = keyfetch.OIDCJWK(kid, iss)
		if nil != err {
			return nil, fmt.Errorf("Bad Request: 'kid' could not be matched to a known public key")
		}
	} else {
		return nil, fmt.Errorf("Bad Request: self-signed tokens with 'jwk' are not supported")
	}

	errs := keypairs.VerifyClaims(pub, jws)
	if 0 != len(errs) {
		strs := []string{}
		for _, err := range errs {
			strs = append(strs, err.Error())
		}
		return nil, fmt.Errorf("invalid jwt:\n%s", strings.Join(strs, "\n\t"))
	}

	return &JWS{
		JWS:     *jws,
		Trusted: true,
		Errors:  nil,
	}, nil
}
