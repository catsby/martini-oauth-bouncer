package bouncer

import (
	"code.google.com/p/goauth2/oauth"
	"encoding/json"
	"fmt"
	"github.com/codegangsta/martini-contrib/sessions"
	"io/ioutil"
	"net/http"
	"os"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("COOKIE_SECRET")))

var oauthConfig = &oauth.Config{
	ClientId:     os.Getenv("HEROKU_OAUTH_ID"),
	ClientSecret: os.Getenv("HEROKU_OAUTH_SECRET"),
	Scope:        "identity",
	AuthURL:      "https://id.heroku.com/oauth/authorize",
	TokenURL:     "https://id.heroku.com/oauth/token",
	RedirectURL:  "http://localhost:5000/heroku/auth/callback",
}

func Bouncer() http.HandlerFunc {
	return func(res http.ResponseWriter, r *http.Request, session sessions.Session) {
		switch r.URL.Path {
		case "/auth/heroku":
			url := oauthConfig.AuthCodeURL("")
			http.Redirect(res, r, url, http.StatusFound)
		case "/auth/heroku/callback":
			code := r.FormValue("code")
			transport := &oauth.Transport{Config: oauthConfig}
			token, err := transport.Exchange(code)
			if err != nil {
				panic(err)
			}
			session.Set("heroku-oauth-token", token.AccessToken)
			// do account things
			requester, err := http.NewRequest("GET", "https://api.heroku.com/account", nil)
			requester.Header.Set("Authorization", "Bearer "+token.AccessToken)
			client := &http.Client{}
			resp, err := client.Do(requester)
			if err != nil {
				panic(err)
			}
			defer resp.Body.Close()
			responseBody, err := ioutil.ReadAll(resp.Body)
			var data map[string]interface{}
			if err := json.Unmarshal(responseBody, &data); err != nil {
				panic(err)
			}
			session.Set("user", data["email"])
			//
			http.Redirect(res, r, "/user", http.StatusFound)
		default:
			fmt.Println("IN DEFAULT")
			if session.Get("heroku-oauth-token") == nil && session.Get("user") == nil {
				url := oauthConfig.AuthCodeURL("")
				http.Redirect(res, r, url, http.StatusFound)
			}
		}
	}
}
