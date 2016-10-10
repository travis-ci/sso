package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/travis-ci/sso"
)

// TODO check nonce lengths
// TODO make sure json encoding works

func main() {
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			fmt.Printf("[INTERNAL] received header: %v\n", req.Header.Get("Travis-State"))
			fmt.Fprintf(w, "Welcome to the home page!")
		})
		log.Fatal(http.ListenAndServe("127.0.0.1:8081", nil))
	}()

	upstreamURL, err := url.Parse("http://127.0.0.1:8081")
	if err != nil {
		panic(err)
	}

	apiURL, err := url.Parse("https://api.travis-ci.org")
	if err != nil {
		panic(err)
	}

	appPublicURL, err := url.Parse("http://localhost:8080")
	if err != nil {
		panic(err)
	}

	sso := &sso.SSO{
		UpstreamURL:   upstreamURL,
		APIURL:        apiURL,
		AppPublicURL:  appPublicURL,
		PublicPath:    "public",
		TemplatePath:  "template",
		EncryptionKey: []byte("sa8OoLei6eWiezah9ohk8Wah6Ow6pee9"),
		CSRFAuthKey:   []byte("oxei9aebonogh1Gaina4ePaitheechei"),
		CSRFSecure:    false,
		Authorized: func(u sso.User) (bool, error) {
			return true, nil
		},
	}

	s := &http.Server{
		Addr:    "127.0.0.1:8080",
		Handler: sso,
	}
	s.ListenAndServe()
}
