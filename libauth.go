package libauth

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"git.rootprojects.org/root/keypairs"
	"git.rootprojects.org/root/keypairs/keyfetch"
)

const oidcIssuersEnv = "OIDC_ISSUERS"
const oidcIssuersInternalEnv = "OIDC_ISSUERS_INTERNAL"

// JWS is keypairs.JWS with added debugging information
type JWS struct {
	keypairs.JWS

	Trusted bool    `json:"trusted"`
	Errors  []error `json:"errors,omitempty"`
}

// IssuerList is the trusted list of token issuers
type IssuerList = keyfetch.Whitelist

// ParseIssuerEnvs will parse ENVs (both comma- and space-delimited) to
// create a trusted IssuerList of public and/or internal issuer URLs.
//
// Example:
//
//	OIDC_ISSUERS='https://example.com/ https://therootcompany.github.io/libauth/'
//	OIDC_ISSUERS_INTERNAL='http://localhost:3000/ http://my-service-name:8080/'
func ParseIssuerEnvs(issuersEnvName, internalEnvName string) (IssuerList, error) {
	if len(issuersEnvName) > 0 {
		issuersEnvName = oidcIssuersEnv
	}
	pubs := os.Getenv(issuersEnvName)
	pubURLs := ParseIssuerListString(pubs)

	if len(internalEnvName) > 0 {
		internalEnvName = oidcIssuersInternalEnv
	}
	internals := os.Getenv(internalEnvName)
	internalURLs := ParseIssuerListString(internals)

	return keyfetch.NewWhitelist(pubURLs, internalURLs)
}

// ParseIssuerListString will Split comma- and/or space-delimited list into a slice
//
// Example:
//
//	"https://example.com/, https://therootcompany.github.io/libauth/"
func ParseIssuerListString(issuerList string) []string {
	issuers := []string{}

	issuerList = strings.TrimSpace(issuerList)
	if len(issuerList) > 0 {
		issuerList = strings.ReplaceAll(issuerList, ",", " ")
		issuers = strings.Fields(issuerList)
	}

	return issuers
}

// VerifyJWT will return a verified InspectableToken if possible, or otherwise as much detail as possible, possibly including an InspectableToken with failed verification.
func VerifyJWT(jwt string, issuers IssuerList, r *http.Request) (*JWS, error) {
	jws := keypairs.JWTToJWS(jwt)
	if nil == jws {
		return nil, fmt.Errorf("bad request: bearer token could not be parsed from 'Authorization' header")
	}

	myJws := &JWS{
		*jws,
		false,
		[]error{},
	}
	if err := myJws.DecodeComponents(); nil != err {
		myJws.Errors = append(myJws.Errors, err)
		return myJws, err
	}

	return VerifyJWS(myJws, issuers, r)
}

// VerifyJWS takes a fully decoded JWS and will return a verified InspectableToken if possible, or otherwise as much detail as possible, possibly including an InspectableToken with failed verification.
func VerifyJWS(jws *JWS, issuers IssuerList, r *http.Request) (*JWS, error) {
	var pub keypairs.PublicKey
	kid, kidOK := jws.Header["kid"].(string)
	iss, issOK := jws.Claims["iss"].(string)

	_, jwkOK := jws.Header["jwk"]
	if !jwkOK {
		if !kidOK || len(kid) == 0 {
			//errs = append(errs, "must have either header.kid or header.jwk")
			return nil, fmt.Errorf("bad request: missing 'kid' identifier")
		} else if !issOK || len(iss) == 0 {
			//errs = append(errs, "payload.iss must exist to complement header.kid")
			return nil, fmt.Errorf("bad request: 'payload.iss' must exist to complement 'header.kid'")
		} else {
			// TODO beware domain fronting, we should set domain statically
			// See https://pkg.go.dev/git.rootprojects.org/root/keypairs@v0.6.2/keyfetch
			// (Caddy does protect against Domain-Fronting by default:
			//     https://github.com/caddyserver/caddy/issues/2500)
			if !issuers.IsTrustedIssuer(iss, r) {
				return nil, fmt.Errorf("unauthorized: 'iss' (%s) is not a trusted issuer", iss)
			}
		}
		var err error
		pub, err = keyfetch.OIDCJWK(kid, iss)
		if nil != err {
			return nil, fmt.Errorf("bad request: 'kid' could not be matched to a known public key: %w", err)
		}
	} else {
		return nil, fmt.Errorf("bad request: self-signed tokens with 'jwk' are not supported")
	}

	errs := keypairs.VerifyClaims(pub, &jws.JWS)
	if len(errs) != 0 {
		strs := []string{}
		for _, err := range errs {
			jws.Errors = append(jws.Errors, err)
			strs = append(strs, err.Error())
		}
		return jws, fmt.Errorf("invalid jwt:\n\t%s", strings.Join(strs, "\n\t"))
	}

	jws.Trusted = true
	return jws, nil
}
