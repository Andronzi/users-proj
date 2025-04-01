package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	AuthServer   string
}

var config Config

func init() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Не удалось загрузить .env: %v", err)
	}
	config = Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURI:  os.Getenv("REDIRECT_URI"),
		AuthServer:   os.Getenv("AUTH_SERVER"),
	}
	if config.ClientID == "" {
		registerClient()
	}
}

func main() {
	http.HandleFunc("/", authorizeHandler)
	http.HandleFunc("/callback", callbackHandler)
	log.Printf("HTTP-клиент запущен на :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func registerClient() {
	url := fmt.Sprintf("%s/v1/clients/register", config.AuthServer)
	reqBody := `{"name":"HTTP Client","redirect_uris":["http://localhost:8081/callback"]}`
	req, err := http.NewRequest("POST", url, strings.NewReader(reqBody))
	if err != nil {
		log.Fatalf("Ошибка создания запроса: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Ошибка регистрации: %v", err)
	}
	defer resp.Body.Close()

	var regResp struct {
		ClientId     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	json.NewDecoder(resp.Body).Decode(resp)
	config.ClientID = regResp.ClientId
	config.ClientSecret = regResp.ClientSecret
	log.Printf("Клиент зарегистрирован: ClientID=%s, ClientSecret=%s", config.ClientID, config.ClientSecret)

	f, _ := os.OpenFile(".env", os.O_APPEND|os.O_WRONLY, 0644)
	fmt.Fprintf(f, "CLIENT_ID=%s\nCLIENT_SECRET=%s\n", config.ClientID, config.ClientSecret)
	f.Close()
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	authURL := fmt.Sprintf("%s/v1/authorize?client_id=%s&redirect_uri=%s&response_type=code&state=xyz123",
		config.AuthServer, config.ClientID, config.RedirectURI)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Отсутствует код или состояние", http.StatusBadRequest)
		return
	}

	token, err := exchangeCodeForToken(code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка получения токена: %v", err), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Токен: %s", token)
}

func exchangeCodeForToken(code string) (string, error) {
	url := fmt.Sprintf("%s/v1/token", config.AuthServer)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(config.ClientID, config.ClientSecret)

	q := req.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Add("code", code)
	q.Add("redirect_uri", config.RedirectURI)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}
	return tokenResp.AccessToken, nil
}
