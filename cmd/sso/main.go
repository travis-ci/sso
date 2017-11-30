package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/travis-ci/sso"
)

var listenAddr = flag.String("listen", "127.0.0.1:8080", "address and port to listen on")

var upstreamURLFlag = flag.String("upstream", "", "upstream url")
var apiURLFlag = flag.String("api", "https://api.travis-ci.org", "api url")
var appPublicURLFlag = flag.String("app", "", "app public url")

var encryptionKey = flag.String("encryption-key", "", "key used for cookie authenticated encryption (32 chars)")
var csrfAuthKey = flag.String("csrf-key", "", "key used for cookie authenticated encryption (32 chars)")

var authorizedUsers = flag.String("authorized-users", "", "comma-separated list of users that are authorized to use the app")

func isDir(pth string) (bool, error) {
	fi, err := os.Stat(pth)
	if err != nil {
		return false, err
	}

	return fi.Mode().IsDir(), nil
}

func main() {
	flag.Parse()

	if *upstreamURLFlag == "" {
		fmt.Printf("error: missing upstream url\n")
		os.Exit(1)
	}
	upstreamURL, err := url.Parse(*upstreamURLFlag)
	if err != nil {
		fmt.Printf("error: invalid upstream url: %v\n", err)
		os.Exit(1)
	}

	if *upstreamURLFlag == "" {
		fmt.Printf("error: missing api url\n")
		os.Exit(1)
	}
	apiURL, err := url.Parse(*apiURLFlag)
	if err != nil {
		fmt.Printf("error: invalid api url: %v\n", err)
		os.Exit(1)
	}

	if *appPublicURLFlag == "" {
		fmt.Printf("error: missing app public url\n")
		os.Exit(1)
	}
	appPublicURL, err := url.Parse(*appPublicURLFlag)
	if err != nil {
		fmt.Printf("error: invalid app public url: %v\n", err)
		os.Exit(1)
	}

	if *encryptionKey == "" {
		fmt.Printf("error: missing encryption-key\n")
		os.Exit(1)
	}
	if len(*encryptionKey) != 32 {
		fmt.Printf("error: invalid encryption-key: length must be exactly 32 bytes\n")
		os.Exit(1)
	}

	if *csrfAuthKey == "" {
		fmt.Printf("error: missing csrf-key\n")
		os.Exit(1)
	}
	if len(*csrfAuthKey) != 32 {
		fmt.Printf("error: invalid csrf-key: length must be exactly 32 bytes\n")
		os.Exit(1)
	}

	if *authorizedUsers == "" {
		fmt.Printf("error: missing authorized-users\n")
		os.Exit(1)
	}

	authorized := make(map[string]bool)
	for _, login := range strings.Split(*authorizedUsers, ",") {
		authorized[strings.Trim(login, " ")] = true
	}

	sso := &sso.SSO{
		UpstreamURL:   upstreamURL,
		APIURL:        apiURL,
		AppPublicURL:  appPublicURL,
		EncryptionKey: []byte(*encryptionKey),
		CSRFAuthKey:   []byte(*csrfAuthKey),
		Authorized: func(u sso.User) (bool, error) {
			return authorized[u.Login], nil
		},
	}

	s := &http.Server{
		Addr:    *listenAddr,
		Handler: sso,
	}
	s.ListenAndServe()
}
