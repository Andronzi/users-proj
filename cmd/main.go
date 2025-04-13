package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"user_project/internal/domain"
	"user_project/internal/repository"
	grpcserver "user_project/internal/transport/grpc"
	"user_project/internal/utils"
	"user_project/internal/utils/blacklist"
	"user_project/internal/utils/middleware"
	users_v1 "user_project/pkg/grpc/users.v1"

	"google.golang.org/protobuf/proto"

	"github.com/go-redis/redis/v8"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/rs/cors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	redisAddr := os.Getenv("REDIS_ADDR")
	secretKey := os.Getenv("SECRET_KEY")

	dsn := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbName, dbPassword)
	db, err := gorm.Open(postgres.Open(dsn))
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")
	db.AutoMigrate(&domain.User{})
	db.AutoMigrate(&domain.Client{})
	db.AutoMigrate(&domain.AuthorizationCode{})
	db.AutoMigrate(&domain.Session{})

	if err := seedClient(db); err != nil {
		log.Fatal(err)
	}

	redisClient := redis.NewClient(&redis.Options{Addr: redisAddr})
	_, err = redisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()

	userRepo := repository.NewUserRepository(db)
	clientRepo := repository.NewClientRepository(db)
	secretKey = "your-secret-key"

	publicLis, _ := net.Listen("tcp", ":50054")
	publicSrv := grpc.NewServer()
	reflection.Register(publicSrv)
	users_v1.RegisterPublicUserServiceServer(publicSrv, grpcserver.NewPublicUserServiceServer(userRepo, clientRepo, redisClient, secretKey))
	go func() {
		log.Printf("Public server listening at %v", publicLis.Addr())
		if err := publicSrv.Serve(publicLis); err != nil {
			log.Fatalf("Failed to serve public: %v", err)
		}
	}()

	roleSafeMethods := map[string]bool{
		"/users.v1.InternalUserService/ListUsers":      true,
		"/users.v1.InternalUserService/AssignAdmin":    true,
		"/users.v1.InternalUserService/CreateUser":     true,
		"/users.v1.InternalUserService/CreateEmployee": true,
		"/users.v1.InternalUserService/BanUser":        true,
	}
	internalLis, _ := net.Listen("tcp", ":50055")
	blacklist := blacklist.NewRedisBlacklist(redisClient, blacklist.UserBlackList, blacklist.TokenBlackList)
	internalSrv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			middleware.BlacklistMiddleware(secretKey, blacklist),
			middleware.RoleRequiredMiddleware(roleSafeMethods),
		),
	)
	reflection.Register(internalSrv)
	users_v1.RegisterInternalUserServiceServer(
		internalSrv,
		grpcserver.NewInternalUserServiceServer(userRepo, redisClient, blacklist, secretKey),
	)
	go func() {
		log.Printf("Internal server listening at %v", internalLis.Addr())
		if err := internalSrv.Serve(internalLis); err != nil {
			log.Fatalf("Failed to serve internal: %v", err)
		}
	}()

	log.Printf("After Internal listening")

	mux := runtime.NewServeMux(
		runtime.WithIncomingHeaderMatcher(func(key string) (string, bool) {
			if key == "Cookie" {
				return "cookie", true
			}
			return runtime.DefaultHeaderMatcher(key)
		}),
		runtime.WithForwardResponseOption(redirectHandler),
	)
	opts := []grpc.DialOption{grpc.WithInsecure()}
	err = users_v1.RegisterPublicUserServiceHandlerFromEndpoint(context.Background(), mux, "localhost:50054", opts)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Before 8082 listening")

	httpMux := http.NewServeMux()
	err = users_v1.RegisterPublicUserServiceHandlerFromEndpoint(context.Background(), mux, "localhost:50054", opts)
	if err != nil {
		log.Fatal(err)
	}
	httpMux.Handle("/", mux)
	http.HandleFunc("/register", registerFormHandler)
	httpMux.HandleFunc("/login", loginFormHandler)

	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	}).Handler(httpMux)

	log.Printf("Gateway запущен на :8082")
	log.Fatal(http.ListenAndServe(":8082", handler))
}

func redirectHandler(ctx context.Context, w http.ResponseWriter, resp proto.Message) error {
	if authResp, ok := resp.(*users_v1.AuthorizeOAuthResponse); ok {
		if authResp.RedirectUri != "" {
			w.Header().Set("Location", authResp.RedirectUri)
			w.WriteHeader(http.StatusFound)
			return nil
		}
	}
	return nil
}

func registerFormHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	if r.Method == "GET" {
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		responseType := r.URL.Query().Get("response_type")
		state := r.URL.Query().Get("state")

		fmt.Fprintf(w, `
            <!DOCTYPE html>
            <html>
            <head><title>Register</title></head>
            <body>
                <form method="post" action="%s/register">
                    <input type="hidden" name="client_id" value="%s">
                    <input type="hidden" name="redirect_uri" value="%s">
                    <input type="hidden" name="response_type" value="%s">
                    <input type="hidden" name="state" value="%s">
                    <label>Email:</label><input type="email" name="email" required><br>
                    <label>Password:</label><input type="password" name="password" required><br>
                    <label>Role:</label><input type="text" name="role" required><br>
                    <button type="submit">Register</button>
                </form>
            </body>
            </html>
        `, "http://localhost:8082", clientID, redirectURI, responseType, state)
	} else if r.Method == "POST" {
		r.ParseForm()
		email := r.FormValue("email")
		password := r.FormValue("password")
		role := r.FormValue("role")
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		// responseType := r.FormValue("response_type")
		// state := r.FormValue("state")

		conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", 50054), grpc.WithInsecure())
		if err != nil {
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			log.Printf("Ошибка %v", err)
			return
		}
		defer conn.Close()

		client := users_v1.NewPublicUserServiceClient(conn)
		resp, err := client.RegisterOAuth(context.Background(), &users_v1.RegisterOAuthRequest{
			Email:    email,
			Password: password,
			Role:     utils.DomainToGrpcRole(domain.Role(role)),
		})
		if err != nil {
			if status.Code(err) == codes.AlreadyExists {
				http.Error(w, "Email already exists", http.StatusConflict)
			} else {
				http.Error(w, "Registration failed", http.StatusInternalServerError)
			}
			log.Printf("Failed registration %v", err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    resp.SessionId,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			MaxAge:   24 * 60 * 60,
		})

		if clientID == "" || redirectURI == "" {
			http.Error(w, "Отсутствуют параметры авторизации", http.StatusBadRequest)
			return
		}
		authURL := fmt.Sprintf("%s/v1/authorize?client_id=%s&redirect_uri=%s&response_type=%s&state=%s",
			"http://localhost:8082", clientID, redirectURI, "code", "state")

		log.Printf("redirect to %s", authURL)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func loginFormHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	if r.Method == "GET" {
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		responseType := r.URL.Query().Get("response_type")
		state := r.URL.Query().Get("state")

		log.Printf("Params: %s, %s", clientID, redirectURI)

		fmt.Fprintf(w, `
            <!DOCTYPE html>
            <html>
            <head><title>Login</title></head>
            <body>
                <form method="post" action="%s/login">
                    <input type="hidden" name="client_id" value="%s">
                    <input type="hidden" name="redirect_uri" value="%s">
                    <input type="hidden" name="response_type" value="%s">
                    <input type="hidden" name="state" value="%s">
                    <label>Email:</label><input type="email" name="email" required><br>
                    <label>Password:</label><input type="password" name="password" required><br>
                    <button type="submit">Login</button>
                </form>
            </body>
            </html>
        `, "http://localhost:8082", clientID, redirectURI, responseType, state)
	} else if r.Method == "POST" {
		r.ParseForm()
		email := r.FormValue("email")
		password := r.FormValue("password")
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		// responseType := r.FormValue("response_type")
		// state := r.FormValue("state")

		conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", 50054), grpc.WithInsecure())
		if err != nil {
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			log.Printf("Ошибка %v", err)
			return
		}
		defer conn.Close()

		client := users_v1.NewPublicUserServiceClient(conn)
		resp, err := client.Login(context.Background(), &users_v1.LoginRequest{
			Email:    email,
			Password: password,
		})
		if err != nil {
			http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
			log.Printf("Failed login %v", err)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    resp.SessionId,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			MaxAge:   24 * 60 * 60,
		})

		// Формируем URL для редиректа на основе параметров формы
		if clientID == "" || redirectURI == "" {
			http.Error(w, "Отсутствуют параметры авторизации", http.StatusBadRequest)
			return
		}
		authURL := fmt.Sprintf("%s/v1/authorize?client_id=%s&redirect_uri=%s&response_type=%s&state=%s",
			"http://localhost:8082", clientID, redirectURI, "code", "state")

		log.Printf("redirect to %s", authURL)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func seedClient(db *gorm.DB) error {
	var count int64
	clientID := "wem7LcxWDUArXEm-0e4nsEjkwsroaXU_"

	err := db.Model(&domain.Client{}).Where("id = ?", clientID).Count(&count).Error
	if err != nil {
		return err
	}

	if count == 0 {
		client := domain.Client{
			ID:          clientID,
			Secret:      "XjDrJbBpJ6akhpwz5Jn070Bypajst3Nkb8wepVWyqEDLjnV4gxsW0nD8zctByj8l",
			Name:        "API_GATEWAY",
			RedirectURI: "http://localhost:3000/",
		}
		return db.Create(&client).Error
	}

	return nil
}
