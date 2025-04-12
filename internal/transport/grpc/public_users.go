package grpc

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
	"user_project/internal/domain"
	"user_project/internal/repository"
	"user_project/internal/utils"
	"user_project/internal/utils/blacklist"
	users_v1 "user_project/pkg/grpc/users.v1"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Claims struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	jwt.StandardClaims
}
type PublicUserServiceServer struct {
	users_v1.UnimplementedPublicUserServiceServer
	UserRepo       *repository.UserRepository
	ClientRepo     *repository.ClientRepository
	Redis          *redis.Client
	RedisBlacklist *blacklist.RedisBlacklist
	SecretKey      string
}

func NewPublicUserServiceServer(userRepo *repository.UserRepository, clientRepo *repository.ClientRepository, redis *redis.Client, secretKey string) *PublicUserServiceServer {
	return &PublicUserServiceServer{
		UserRepo:       userRepo,
		ClientRepo:     clientRepo,
		Redis:          redis,
		RedisBlacklist: blacklist.NewRedisBlacklist(redis, blacklist.UserBlackList, blacklist.TokenBlackList),
		SecretKey:      secretKey,
	}
}

func (s *PublicUserServiceServer) RegisterClient(ctx context.Context, req *users_v1.RegisterClientRequest) (*users_v1.RegisterClientResponse, error) {
	clientID := utils.GenerateRandomString(32)
	clientSecret := utils.GenerateRandomString(64)

	client := &domain.Client{
		ID:          clientID,
		Secret:      clientSecret,
		RedirectURI: req.RedirectUri,
		Name:        req.Name,
	}

	if err := s.ClientRepo.CreateClient(ctx, client); err != nil {
		return nil, status.Error(codes.Internal, "Не удалось создать клиента")
	}

	return &users_v1.RegisterClientResponse{
		ClientId:     clientID,
		ClientSecret: clientSecret,
	}, nil
}

func (s *PublicUserServiceServer) Register(ctx context.Context, req *users_v1.RegisterRequest) (*users_v1.RegisterResponse, error) {
	exists, err := s.UserRepo.ExistsByEmail(ctx, req.Email)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to check user existence")
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "Email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to hash password")
	}

	user := &domain.User{
		Email:    req.Email,
		Password: string(hashedPassword),
		Role:     utils.GrpcToDomainRole(req.Role),
	}
	if err := s.UserRepo.Create(ctx, user); err != nil {
		return nil, status.Error(codes.Internal, "Failed to create user")
	}

	token, err := utils.GenerateToken(utils.TokenParams{ID: user.ID, Role: string(user.Role)}, s.SecretKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate token")
	}

	return &users_v1.RegisterResponse{
		Message: "User created successfully",
		Token:   token,
	}, nil
}

func (s *PublicUserServiceServer) Authorize(ctx context.Context, req *users_v1.AuthorizeRequest) (*users_v1.AuthorizeResponse, error) {
	if req.ResponseType != "code" {
		return nil, status.Error(codes.InvalidArgument, "Неподдерживаемый тип ответа")
	}

	client, err := s.ClientRepo.GetClientByID(ctx, req.ClientId)
	if err != nil || client.RedirectURI != req.RedirectUri {
		return nil, status.Error(codes.InvalidArgument, "Неверный клиент или redirect_uri")
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Printf("No metadata in request")
		return &users_v1.AuthorizeResponse{
			RedirectUri: "http://localhost:8080/login",
			Message:     "Требуется аутентификация",
		}, nil
	}

	sessionID := ""
	if cookies := md.Get("cookie"); len(cookies) > 0 {
		cookieStr := cookies[0]
		cookiesParsed, err := (&http.Request{Header: http.Header{"Cookie": []string{cookieStr}}}).Cookie("session_id")
		if err == nil && cookiesParsed != nil {
			sessionID = cookiesParsed.Value
			log.Printf("Extracted session_id=%s from cookie", sessionID)
		}
	}

	if sessionID == "" {
		log.Printf("No session_id found in metadata")
		return &users_v1.AuthorizeResponse{
			RedirectUri: "http://localhost:8080/login",
			Message:     "Требуется аутентификация",
		}, nil
	}

	session, err := s.ClientRepo.GetSession(ctx, sessionID)
	if err != nil || session.IsExpired() {
		return &users_v1.AuthorizeResponse{
			RedirectUri: "http://localhost:8080/login",
			Message:     "Сессия недействительна",
		}, nil
	}

	code := utils.GenerateRandomString(32)
	authCode := &domain.AuthorizationCode{
		Code:        code,
		UserID:      session.UserID,
		ClientID:    req.ClientId,
		RedirectURI: req.RedirectUri,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	if err := s.ClientRepo.SaveAuthorizationCode(ctx, authCode); err != nil {
		return nil, status.Error(codes.Internal, "Не удалось сохранить код")
	}
	redirectURI := fmt.Sprintf("%s?code=%s&state=%s", req.RedirectUri, code, req.State)
	return &users_v1.AuthorizeResponse{
		RedirectUri: redirectURI,
		Message:     "Успешная авторизация",
	}, nil
}

func (s *PublicUserServiceServer) Token(ctx context.Context, req *users_v1.TokenRequest) (*users_v1.TokenResponse, error) {
	if req.GrantType != "authorization_code" {
		return nil, status.Error(codes.InvalidArgument, "Неподдерживаемый тип гранта")
	}
	authCode, err := s.ClientRepo.GetAuthorizationCode(ctx, req.Code)
	if err != nil || authCode.IsExpired() {
		return nil, status.Error(codes.InvalidArgument, "Неверный или просроченный код")
	}
	if authCode.RedirectURI != req.RedirectUri || authCode.ClientID != req.ClientId {
		return nil, status.Error(codes.InvalidArgument, "Неверный redirect_uri или client_id")
	}

	client, err := s.ClientRepo.GetClientByID(ctx, req.ClientId)
	if err != nil || client.Secret != req.ClientSecret {
		return nil, status.Error(codes.Unauthenticated, "Неверный client_secret")
	}

	user, err := s.UserRepo.FindByID(ctx, authCode.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "Не удалось получить пользователя")
	}

	token, err := utils.GenerateToken(utils.TokenParams{ID: user.ID, Role: string(user.Role)}, s.SecretKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Не удалось сгенерировать токен")
	}
	return &users_v1.TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func (s *PublicUserServiceServer) Login(ctx context.Context, req *users_v1.LoginRequest) (*users_v1.LoginResponse, error) {
	user, err := s.UserRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, status.Error(codes.NotFound, "Пользователь не найден")
	}
	if err := utils.VerifyPassword(user.Password, req.Password); err != nil {
		return nil, status.Error(codes.Unauthenticated, "Неверный пароль")
	}

	sessionID := utils.GenerateRandomString(32)
	session := &domain.Session{
		ID:        sessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := s.ClientRepo.CreateSession(ctx, session); err != nil {
		return nil, status.Error(codes.Internal, "Не удалось создать сессию")
	}
	return &users_v1.LoginResponse{
		SessionId: sessionID,
		Message:   "Успешный вход",
	}, nil
}

func (s *PublicUserServiceServer) Revalidate(ctx context.Context, req *users_v1.RevalidateRequest) (*users_v1.RevalidateResponse, error) {
	tokenString, err := utils.ExtractTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	claims, err := utils.ParseAndValidateToken(tokenString, s.SecretKey, jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, err
	}

	if err := s.RedisBlacklist.CheckUser(ctx, claims.ID); err != nil {
		return nil, err
	}

	if err := s.RedisBlacklist.CheckToken(ctx, tokenString); err != nil {
		return nil, err
	}

	token, err := utils.GenerateToken(utils.TokenParams{ID: claims.ID, Role: string(claims.Role)}, s.SecretKey)

	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate new token")
	}

	return &users_v1.RevalidateResponse{
		Token:   token,
		Message: "Token revalidated successfully",
	}, nil
}

func (s *PublicUserServiceServer) Logout(ctx context.Context, req *users_v1.LogoutRequest) (*users_v1.LogoutResponse, error) {
	tokenString, err := utils.ExtractTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	_, err = utils.ParseAndValidateToken(tokenString, s.SecretKey)
	if err != nil {
		return nil, err
	}

	if err := s.RedisBlacklist.CheckToken(ctx, tokenString); err != nil {
		return nil, err
	}

	return &users_v1.LogoutResponse{Message: "Logged out successfully"}, nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
