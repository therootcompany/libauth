package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"

	"git.rootprojects.org/root/keypairs/keyfetch"
	"git.rootprojects.org/root/libauth/chiauth"
)

func main() {
	r := chi.NewRouter()

	whitelist, err := keyfetch.NewWhitelist([]string{"https://therootcompany.github.io/libauth/"})
	if nil != err {
		panic(err)
	}

	// Unauthenticated Routes
	r.Group(func(r chi.Router) {
		r.Post("/api/hello", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{ "message": "Hello, World!" }`))
		})
	})

	// Authenticated Routes
	r.Group(func(r chi.Router) {
		tokenVerifier := chiauth.NewTokenVerifier(chiauth.VerificationParams{
			Issuers:  whitelist,
			Optional: true,
		})
		r.Use(tokenVerifier)

		r.Post("/api/users/profile", func(w http.ResponseWriter, r *http.Request) {
			jws := chiauth.GetJWS(r)
			if nil == jws || !jws.Trusted {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			userID := jws.Claims["sub"].(string)

			b, _ := json.MarshalIndent(struct {
				UserID string `json:"user_id"`
			}{
				UserID: userID,
			}, "", "  ")
			w.Write(append(b, '\n'))
		})
	})

	// ...

	bindAddr := ":3000"
	fmt.Println("Listening on", bindAddr)

	fmt.Println("")
	fmt.Println("Try this:")
	fmt.Println("")
	fmt.Println("")
	cwd, _ := os.Getwd()
	fmt.Println("    pushd", cwd)
	fmt.Println("")
	fmt.Println("    my_jwt=\"$(cat ./jwt.txt)\"")
	fmt.Println(
		strings.Join(
			[]string{
				"    curl -X POST http://localhost:3000/api/users/profile",
				"        -H \"Authorization: Bearer ${my_jwt}\"",
				"        -H 'Content-Type: application/json'",
				"        --data-binary '{ \"foo\": \"bar\" }'",
			},
			" \\\n",
		),
	)
	fmt.Println("")

	http.ListenAndServe(bindAddr, r)
}
