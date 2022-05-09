package chiauth

import (
	"context"
	"log"
	"net/http"
	"strings"

	"git.rootprojects.org/root/keypairs/keyfetch"
	"git.rootprojects.org/root/libauth"
)

type ctxKey string

// JWSKey is used to get the InspectableToken from http.Request.Context().Value(chiauth.JWSKey)
var JWSKey = ctxKey("jws")

// VerificationParams specify the Issuer and whether or not the token is Optional (if provided, it must pass verification)
type VerificationParams struct {
	Issuers  keyfetch.Whitelist
	Optional bool
	/*
		ExpLeeway  int
		NbfLeeway  int
		SelfSigned bool
		PubKey     keypairs.PublicKey
	*/
}

// NewTokenVerifier returns a token-verifying middleware
//
//   tokenVerifier := chiauth.NewTokenVerifier(chiauth.VerificationParams{
//		Issuers: keyfetch.Whitelist([]string{"https://accounts.google.com"}),
//		Optional: false,
//   })
//   r.Use(tokenVerifier)
//
//   r.Post("/api/users/profile", func(w http.ResponseWriter, r *http.Request) {
//		ctx := r.Context()
//		jws, ok := ctx.Value(chiauth.JWSKey).(*libauth.JWS)
//   })
//
func NewTokenVerifier(opts VerificationParams) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// just setting a default, other handlers can change this

			token := r.Header.Get("Authorization")
			log.Printf("%s %s %s\n", r.Method, r.URL.Path, token)

			if "" == token {
				if opts.Optional {
					next.ServeHTTP(w, r)
					return
				}

				http.Error(
					w,
					"Bad Format: missing Authorization header and 'access_token' query",
					http.StatusBadRequest,
				)
				return
			}

			parts := strings.Split(token, " ")
			if 2 != len(parts) {
				http.Error(
					w,
					"Bad Format: expected Authorization header to be in the format of 'Bearer <Token>'",
					http.StatusBadRequest,
				)
				return
			}
			token = parts[1]

			inspected, err := libauth.VerifyJWT(token, opts.Issuers, r)
			if nil != err {
				w.WriteHeader(http.StatusBadRequest)
				errmsg := "Invalid Token: " + err.Error() + "\n"
				w.Write([]byte(errmsg))
				return
			}
			if !inspected.Trusted {
				http.Error(w, "Bad Token Signature", http.StatusBadRequest)
				return
			}

			ctx := context.WithValue(r.Context(), JWSKey, inspected)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
