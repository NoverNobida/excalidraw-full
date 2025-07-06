package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"excalidraw-complete/core"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var (
	oauthConfig *oauth2.Config
	jwtSecret   []byte
)

const oauthStateString = "random"

// AppClaims represents the custom claims for the JWT.
type AppClaims struct {
	jwt.RegisteredClaims
	Login     string `json:"login"`
	AvatarURL string `json:"avatarUrl"`
	Name      string `json:"name"`
}

func Init() {
	oauthConfig = &oauth2.Config{
		ClientID:     os.Getenv("LINUXDO_CLIENT_ID"),
		ClientSecret: os.Getenv("LINUXDO_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("LINUXDO_REDIRECT_URL"),
		Scopes:       []string{"read:user", "user:email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://connect.linux.do/oauth2/authorize",
			TokenURL: "https://connect.linux.do/oauth2/token",
		},
	}
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))

	if oauthConfig.ClientID == "" || oauthConfig.ClientSecret == "" {
		logrus.Warn("OAuth credentials are not set. Authentication routes will not work.")
	}
	if len(jwtSecret) == 0 {
		logrus.Warn("JWT_SECRET is not set. Authentication routes will not work.")
	}
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := &http.Cookie{
		Name:     "oauthstate",
		Value:    state,
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
	}
	http.SetCookie(w, cookie)
	return state
}

func HandleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	if oauthConfig.ClientID == "" {
		http.Error(w, "OAuth is not configured", http.StatusInternalServerError)
		return
	}
	state := generateStateOauthCookie(w)
	url := oauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if oauthConfig.ClientID == "" {
		http.Error(w, "OAuth is not configured", http.StatusInternalServerError)
		return
	}

	oauthState, _ := r.Cookie("oauthstate")
	if r.FormValue("state") != oauthState.Value {
		logrus.Error("invalid oauth state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	token, err := oauthConfig.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		logrus.Errorf("failed to exchange token: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://connect.linux.do/api/user")
	if err != nil {
		logrus.Errorf("failed to get user from oauth provider: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("failed to read oauth provider response body: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	var oauthUser struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
		Name      string `json:"name"`
	}

	if err := json.Unmarshal(body, &oauthUser); err != nil {
		logrus.Errorf("failed to unmarshal oauth user: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// For now we don't have a user database, so we create a user object on the fly.
	// In phase 3, we will save/get the user from the database here.
	user := &core.User{
		GitHubID:  oauthUser.ID,
		Login:     oauthUser.Login,
		AvatarURL: oauthUser.AvatarURL,
		Name:      oauthUser.Name,
	}

	jwtToken, err := createJWT(user)
	if err != nil {
		logrus.Errorf("failed to create JWT: %s", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Redirect to frontend with token
	http.Redirect(w, r, fmt.Sprintf("/?token=%s", jwtToken), http.StatusTemporaryRedirect)
}

func createJWT(user *core.User) (string, error) {
	claims := AppClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", user.GitHubID),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 7)), // 1 week
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Login:     user.Login,
		AvatarURL: user.AvatarURL,
		Name:      user.Name,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ParseJWT(tokenString string) (*AppClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AppClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*AppClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
