package sso

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
)

type Options struct {
	UpstreamURL string
	APIURL      string
	PublicPath  string
	Authorized  func(User) (bool, error)
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

type SSOState struct {
	User User
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

func (o Options) HandleRequest(req http.Request, w *http.ResponseWriter) {
	if strings.HasPrefix(req.URL.Path, "/__travis__") {
		return o.handleStatic(req, w)
	}

	if isLogin(req) {
		return o.handleLogin(req, w)
	}

	if isLogout(req) {
		return o.handleLogout(req, w)
	}

	if isAuthenticated(req) {
		return o.handleProxy(req, w)
	}

	if isHandshake(req) {
		return o.handleHandshake(req, w)
	}
}

func (o Options) handleStatic(req http.Request, w *http.ResponseWriter) {
}

func (o Options) handleProxy(req http.Request, w *http.ResponseWriter) {
}

func (o Options) handleLogin(req http.Request, w *http.ResponseWriter) {
	token, err := ssoToken(request)
	if err != nil {
		return err
	}

	url = o.APIURL + "/users?access_token=%s"
	apiReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	apiReq.Header.Add("Accept", "application/vnd.travis-ci.2+json")
	apiResp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer apiResp.Body.Close()

	// TODO: check response code

	var m APIMessage
	err = json.NewDecoder(apiResp.Body).Decode(&m)
	if err != nil {
		return err
	}

	user := m.User

	ok, err := o.Authorized(user)
	if err != nil {
		return err
	}

	if !ok {
		http.Error(w, fmt.Sprintf("access denied for user %s", user.Login), 403)
		return
	}

	// TODO: generate signed cookie containing user
	ssoState = &SSOState{
		User: user,
		Token: token,
	}

	b, err := json.Marshal(user)
	if err != nil {
		return err
	}

	encryptedCookie = encrypt(b)

	httpSetCookie(w, &http.Cookie{
		Name:  "travis.sso",
		Value: signedCookie,
	})

	return ssoState, nil
}

func (o Options) handleHandshake(req http.Request, w *http.ResponseWriter) {
	if req.Method != "GET" && req.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, fmt.Sprintf(`must be <a href="%s">GET</a> request`, req.URL), 405)
		return
	}

	t.Execute(w, map[string]string{
		"Public":   o.PublicPath,
		"Endpoint": o.APIURL,
		"Origin":   r.URL,
		"CSRF":     "",
	})
}

func (o Options) handleLogout(req http.Request, w *http.ResponseWriter) {
	httpSetCookie(w, &http.Cookie{
		Name:  "travis.sso",
		Value: "",
		Expires: time.Date(1970, time.January, 1, 1, 0, 0, 0, time.UTC)
	})

	w.Write([]byte("logged out"))
}

func ssoToken(req http.Request) {
	if req.Method == "POST" {
		return req.FormValue("sso_token")
	}
	return ""
}

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
