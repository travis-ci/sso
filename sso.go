package sso

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vulcand/oxy/forward"
)

type SSO struct {
	UpstreamURL   *url.URL
	APIURL        *url.URL
	AppPublicURL  *url.URL
	PublicPath    string
	EncryptionKey []byte
	Authorized    func(User) (bool, error)
}

type User struct {
	ID            int
	Name          string
	Login         string
	Email         string
	GravatarID    string
	IsSyncing     bool
	SyncedAt      string
	CorrectScopes bool
	CreatedAt     string
}

type APIMessage struct {
	User User
}

type State struct {
	User  User
	Token string
}

var t *template.Template

func init() {
	var err error
	t, err = template.ParseFiles("template/login.html")
	if err != nil {
		log.Fatalf("error compiling template: %v", err)
	}
}

// rewrite request for forwarding
func (sso SSO) Rewrite(r *http.Request) {

}

func (sso SSO) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	fmt.Println("ServeHTTP")

	mux := http.NewServeMux()
	mux.HandleFunc("/favicon.ico", sso.handleEmpty)
	mux.HandleFunc("/foo", sso.handleHello)
	mux.HandleFunc("/bar", sso.handleHello)
	mux.Handle("/sso/static/", sso.handleStatic(w, req))
	mux.HandleFunc("/sso/login", sso.handleLogin)
	mux.HandleFunc("/sso/logout", sso.handleLogout)
	mux.HandleFunc("/", http.HandlerFunc(sso.handleRequest))

	mux.ServeHTTP(w, req)
}

func (sso SSO) handleEmpty(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(204)
}

func (sso SSO) handleHello(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("hello"))
}

func (sso SSO) handleStatic(w http.ResponseWriter, req *http.Request) http.Handler {
	return http.StripPrefix("/sso/static/", http.FileServer(http.Dir(sso.PublicPath)))
}

func (sso SSO) handleRequest(w http.ResponseWriter, req *http.Request) {
	fmt.Println("handleRequest")

	state, err := sso.stateFromRequest(req)
	if err != nil && err != http.ErrNoCookie {
		http.Error(w, err.Error(), 500)
		return
	}

	if state != nil {
		// we have a state => we are authenticated
		sso.handleProxy(w, req, state)
		return
	}

	sso.handleHandshake(w, req)
}

func (sso SSO) handleProxy(w http.ResponseWriter, req *http.Request, state *State) {
	fmt.Println("handleProxy")

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

func (sso SSO) handleLogin(w http.ResponseWriter, req *http.Request) {
	fmt.Println("handleLogin")

	token := ""
	if req.Method == "POST" {
		token = req.FormValue("sso_token")
	}

	if token == "" {
		log.Println("no token found, try again")
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

	// TODO: check response code
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

	domain := sso.AppPublicURL.Host
	index := strings.Index(domain, ":")
	if index > 0 {
		domain = domain[:index]
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "travis.sso",
		Value:   encodedCookie,
		Path:    "/",
		Domain:  domain,
		Expires: time.Now().Add(365 * 24 * time.Hour),
	})

	fmt.Println("cookies set, redirecting back")

	http.Redirect(w, req, "/", http.StatusFound)
}

func (sso SSO) handleHandshake(w http.ResponseWriter, req *http.Request) {
	fmt.Println("handleHandshake")

	if req.Method != "GET" && req.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, fmt.Sprintf(`must be <a href="%s">GET</a> request`, req.URL), 405)
		return
	}

	t.Execute(w, map[string]string{
		"Public":   "/sso/static",
		"Endpoint": sso.APIURL.String(),
		"Origin":   sso.AppPublicURL.String(),
		"CSRF":     "",
	})
}

func (sso SSO) handleLogout(w http.ResponseWriter, req *http.Request) {
	fmt.Println("handleLogout")

	domain := sso.AppPublicURL.Host
	index := strings.Index(domain, ":")
	if index > 0 {
		domain = domain[:index]
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "travis.sso",
		Value:   "",
		Path:    "/",
		Domain:  domain,
		Expires: time.Date(1970, time.January, 1, 1, 0, 0, 0, time.UTC),
	})

	w.Write([]byte("logged out"))
}

func (sso SSO) stateFromRequest(req *http.Request) (*State, error) {
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
