# libauth

LibAuth for Go - A modern authentication framework that feels as light as a library.

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

	whitelist, err := keyfetch.NewWhitelist([]string{"https://accounts.google.com"})
	if nil != err {
		panic(err)
	}
	tokenVerifier := chiauth.NewTokenVerifier(chiauth.VerificationParams{
		Issuers:  whitelist,
		Optional: false,
	})
	r.Use(tokenVerifier)

	r.Post("/api/users/profile", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		jws, ok := ctx.Value(chiauth.JWSKey).(*libauth.JWS)
		if !ok || !jws.Trusted {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}

		userID := jws.Claims["sub"].(string)
		// ...
	})

    // ...
}
```

How to pass an auth token:

```bash
curl -X POST http://localhost:3000/api/users/profile \
    -H 'Authorization: Bearer <xxxx.yyyy.zzzz>' \
    -H 'Content-Type: application/json' \
    --raw-data '{ "foo": "bar" }'
```
