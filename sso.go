package sso

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/elazarl/go-bindata-assetfs"
	"github.com/gorilla/csrf"
	"github.com/vulcand/oxy/forward"
)

var (
	templateLogin  *template.Template
	templateLogout *template.Template
)

func init() {
	templateLogin = mustCompileAssetTemplate("login", "template/login.html")
	templateLogout = mustCompileAssetTemplate("logout", "template/logout.html")
}

func mustCompileAssetTemplate(templateName string, filename string) *template.Template {
	templateHTML, err := Asset(filename)
	if err != nil {
		log.Fatalf("could not find template %s in bindata: %v", filename, err)
	}
	return template.Must(template.New(templateName).Parse(string(templateHTML)))
}

func debug(msg string) {
	if os.Getenv("DEBUG") == "1" || os.Getenv("DEBUG") == "true" {
		log.Println(msg)
	}
}

type SSO struct {
	UpstreamURL    *url.URL
	APIURL         *url.URL
	AppPublicURL   *url.URL
	EncryptionKey  []byte
	CSRFAuthKey    []byte
	BasicAuthToken []byte
	Authorized     func(User) (bool, error)
}

type User struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	Login         string `json:"login"`
	Email         string `json:"email"`
	GravatarID    string `json:"gravatar_id"`
	IsSyncing     bool   `json:"is_syncing"`
	SyncedAt      string `json:"synced_at"`
	CorrectScopes bool   `json:"correct_scopes"`
	CreatedAt     string `json:"created_at"`
}

type APIMessage struct {
	User User `json:"user"`
}

type State struct {
	User  User   `json:"user"`
	Token string `json:"token"`
}

func (sso *SSO) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	debug("ServeHTTP")

	// TODO: HSTS
	if sso.AppPublicURL.Scheme == "https" && req.URL.Scheme != "https" && req.Header.Get("x-forwarded-proto") != "https" {
		http.Redirect(w, req, sso.AppPublicURL.String(), http.StatusFound)
		return
	}

	mux := http.NewServeMux()
	mux.Handle("/sso/static/", sso.handleStatic(w, req))
	mux.HandleFunc("/favicon.ico", sso.handleEmpty)
	mux.HandleFunc("/sso/login", sso.handleLogin)
	mux.Handle("/sso/logout", sso.csrfProtectHandler(sso.handleLogout))
	mux.HandleFunc("/", sso.handleRequest)

	mux.ServeHTTP(w, req)
}

func (sso *SSO) csrfProtectHandler(handler http.HandlerFunc) http.Handler {
	return csrf.Protect(
		sso.CSRFAuthKey,
		csrf.FieldName("authenticity_token"),
		csrf.Path("/"),
		csrf.Domain(domainFromHost(sso.AppPublicURL.Host)),
		csrf.Secure(sso.AppPublicURL.Scheme == "https"),
	)(handler)
}

func (sso *SSO) handleEmpty(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(204)
}

func (sso *SSO) handleStatic(w http.ResponseWriter, req *http.Request) http.Handler {
	assetDir := &assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, AssetInfo: AssetInfo, Prefix: "static"}
	return http.StripPrefix("/sso/static/", http.FileServer(assetDir))
}

func (sso *SSO) handleRequest(w http.ResponseWriter, req *http.Request) {
	debug("handleRequest")

	state, err := sso.stateFromRequest(req)
	if err != nil && err != http.ErrNoCookie {
		// decoding state failed
		// could be an issue with the cookie, remove it
		sso.setLogoutCookie(w)
		http.Error(w, err.Error(), 500)
		return
	}

	if state != nil {
		// we have a state => we are authenticated
		sso.handleProxy(w, req, state)
		return
	}

	if sso.authenticatedViaBasicAuthToken(req) {
		// we are authenticated via basic auth token, bypass sso authentication
		sso.handleProxyBypass(w, req)
		return
	}

	sso.handleHandshake(w, req)
}

func (sso *SSO) handleProxy(w http.ResponseWriter, req *http.Request, state *State) {
	debug("handleProxy")

	b, err := json.Marshal(state)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	req.URL.Scheme = sso.UpstreamURL.Scheme
	req.URL.Host = sso.UpstreamURL.Host
	req.Header.Add("Travis-State", string(b))

	fwd, _ := forward.New()
	fwd.ServeHTTP(w, req)
}

func (sso *SSO) handleProxyBypass(w http.ResponseWriter, req *http.Request) {
	debug("handleProxyBypass")

	req.URL.Scheme = sso.UpstreamURL.Scheme
	req.URL.Host = sso.UpstreamURL.Host

	fwd, _ := forward.New()
	fwd.ServeHTTP(w, req)
}

func (sso *SSO) handleLogin(w http.ResponseWriter, req *http.Request) {
	debug("handleLogin")

	token := ""
	if req.Method == "POST" {
		token = req.FormValue("token")
	}

	if token == "" {
		debug("no token found, try again")
		http.Redirect(w, req, "/", http.StatusFound)
		return
	}

	url := *sso.APIURL

	q := url.Query()
	q.Add("access_token", token)

	url.Path = "/users"
	url.RawQuery = q.Encode()

	apiReq, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	client := &http.Client{}

	apiReq.Header.Add("Accept", "application/vnd.travis-ci.2+json")
	apiResp, err := client.Do(apiReq)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer apiResp.Body.Close()

	if apiResp.StatusCode != http.StatusOK {
		content, _ := ioutil.ReadAll(apiResp.Body)
		http.Error(w, fmt.Sprintf("upstream error, code=%v, body=%v\n", apiResp.StatusCode, string(content)), 500)
		return
	}

	var m APIMessage
	err = json.NewDecoder(apiResp.Body).Decode(&m)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	user := m.User

	ok, err := sso.Authorized(user)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if !ok {
		http.Error(w, fmt.Sprintf("access denied for user %s", user.Login), 403)
		return
	}

	state := &State{
		User:  user,
		Token: token,
	}

	b, err := json.Marshal(state)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	encryptedCookie, nonce, err := encrypt(b, sso.EncryptionKey)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	encryptedCookie = append(nonce, encryptedCookie...)
	encodedCookie := base64.StdEncoding.EncodeToString(encryptedCookie)

	http.SetCookie(w, &http.Cookie{
		Name:    "travis.sso",
		Value:   encodedCookie,
		Path:    "/",
		Domain:  domainFromHost(sso.AppPublicURL.Host),
		Expires: time.Now().Add(365 * 24 * time.Hour),
	})

	debug("cookies set, redirecting back")

	http.Redirect(w, req, "/", http.StatusFound)
}

func (sso *SSO) handleHandshake(w http.ResponseWriter, req *http.Request) {
	debug("handleHandshake")

	if req.Method != "GET" && req.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, fmt.Sprintf(`must be <a href="%s">GET</a> request`, req.URL), 405)
		return
	}

	templateLogin.Execute(w, map[string]interface{}{
		"Public":   "/sso/static",
		"Endpoint": sso.APIURL.String(),
		"Origin":   sso.AppPublicURL.String(),
	})
}

func (sso *SSO) handleLogout(w http.ResponseWriter, req *http.Request) {
	debug("handleLogout")

	if req.Method != "POST" {
		w.Header().Add("Content-Type", "text/html; encoding=UTF-8")
		templateLogout.Execute(w, map[string]interface{}{
			"CSRF": csrf.Token(req),
		})
		return
	}

	sso.setLogoutCookie(w)

	w.Write([]byte("logged out"))
}

func (sso *SSO) authenticatedViaBasicAuthToken(req *http.Request) bool {
	if len(sso.BasicAuthToken) == 0 {
		return false
	}

	user, pass, ok := req.BasicAuth()
	if !ok {
		return false
	}

	if user == "token" && subtle.ConstantTimeCompare([]byte(pass), sso.BasicAuthToken) == 1 {
		return true
	}
	return false
}

func (sso *SSO) stateFromRequest(req *http.Request) (*State, error) {
	cookie, err := req.Cookie("travis.sso")
	if err == http.ErrNoCookie {
		return nil, http.ErrNoCookie
	}
	if err != nil {
		return nil, err
	}

	decodedCookie, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, err
	}

	encryptedCookie := []byte(decodedCookie)

	nonce := encryptedCookie[:12]
	encryptedCookie = encryptedCookie[12:]

	if len(nonce) != 12 {
		return nil, errors.New("nonce must be 12 characters in length")
	}

	if len(encryptedCookie) == 0 {
		return nil, errors.New("encrypted cookie missing")
	}

	b, err := decrypt(encryptedCookie, nonce, sso.EncryptionKey)
	if err != nil {
		return nil, err
	}

	var state *State
	err = json.NewDecoder(bytes.NewReader(b)).Decode(&state)
	if err != nil {
		return nil, err
	}

	return state, nil
}

func (sso *SSO) setLogoutCookie(w http.ResponseWriter) {
	cookieNames := []string{"travis.sso", "_gorilla_csrf"}
	for _, cookieName := range cookieNames {
		http.SetCookie(w, &http.Cookie{
			Name:    cookieName,
			Value:   "",
			Path:    "/",
			Domain:  domainFromHost(sso.AppPublicURL.Host),
			Expires: time.Date(1970, time.January, 1, 1, 0, 0, 0, time.UTC),
		})
	}
}

func domainFromHost(host string) string {
	index := strings.Index(host, ":")
	if index > 0 {
		return host[:index]
	}
	return host
}

// https://gist.github.com/kkirsche/e28da6754c39d5e7ea10

func encrypt(plaintext, key []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	return aesgcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

func decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
