# [libauth](https://git.rootprojects.org/root/libauth)

LibAuth for Go - A modern authentication framework that feels as light as a
library.

[![godoc_button]][godoc]

[godoc]: https://pkg.go.dev/git.rootprojects.org/root/libauth?tab=versions
[godoc_button]: https://godoc.org/git.rootprojects.org/root/libauth?status.svg

## Example Usage

How to verify a valid, trusted token as `chi` middleware:

```go
package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"git.rootprojects.org/root/keypairs/keyfetch"
	"git.rootprojects.org/root/libauth"
	"git.rootprojects.org/root/libauth/chiauth"
)

func main() {
	r := chi.NewRouter()

	whitelist, err := keyfetch.NewWhitelist([]string{"https://therootcompany.github.io/libauth/"})
	if nil != err {
		panic(err)
	}
	tokenVerifier := chiauth.NewTokenVerifier(chiauth.VerificationParams{
		Issuers:  whitelist,
		Optional: false,
	})
	r.Use(tokenVerifier)

	r.Post("/api/users/profile", func(w http.ResponseWriter, r *http.Request) {
		jws := chiauth.GetJWS(r)
		if nil == jws || !jws.Trusted {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		userID := jws.Claims["sub"].(string)
		// ...
	})

    // ...
}
```

How to create a demo token with [keypairs][https://webinstall.dev/keypairs]:

```bash
my_key='./examples/privkey.ec.jwk.json'
my_claims='{
    "iss": "https://therootcompany.github.io/libauth/",
    "sub": "1",
    "email_verified": false,
    "email": "jo@example.com"
}'

keypairs sign \
    --exp 1h \
    "${my_key}" \
    "${my_claims}" \
    > jwt.txt
    2> jws.json
```

How to pass an auth token:

```bash
pushd ./examples
go run ./server.go
```

```bash
my_token="$(cat ./examples/jwt.txt)"

curl -X POST http://localhost:3000/api/users/profile \
    -H "Authorization: Bearer ${my_token}" \
    -H 'Content-Type: application/json' \
    --data-binary '{ "foo": "bar" }'
```

## Example OIDC Discovery URLs

-   Demo:
    <https://therootcompany.github.io/libauth/.well-known/openid-configuration>
-   Auth0: <https://example.auth0.com/.well-known/openid-configuration>
-   Okta: <https://example.okta.com/.well-known/openid-configuration>
-   Google: <https://accounts.google.com/.well-known/openid-configuration>
