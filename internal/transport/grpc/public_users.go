package grpc

import (
	"context"
	"strings"
	"time"
	"user_project/internal/domain"
	"user_project/internal/repository"
	"user_project/internal/utils"
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
	Repo      *repository.UserRepository
	Redis     *redis.Client
	SecretKey string
}

func NewPublicUserServiceServer(repo *repository.UserRepository, redis *redis.Client, secretKey string) *PublicUserServiceServer {
	return &PublicUserServiceServer{
		Repo:      repo,
		Redis:     redis,
		SecretKey: secretKey,
	}
}

func (s *PublicUserServiceServer) Register(ctx context.Context, req *users_v1.RegisterRequest) (*users_v1.RegisterResponse, error) {
	exists, err := s.Repo.ExistsByEmail(ctx, req.Email)
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
	if err := s.Repo.Create(ctx, user); err != nil {
		return nil, status.Error(codes.Internal, "Failed to create user")
	}

	token, err := utils.GenerateToken(user, s.SecretKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate token")
	}

	return &users_v1.RegisterResponse{
		Message: "User created successfully",
		Token:   token,
	}, nil
}

func (s *PublicUserServiceServer) Login(ctx context.Context, req *users_v1.LoginRequest) (*users_v1.LoginResponse, error) {
	user, err := s.Repo.FindByEmail(ctx, req.Email)
	if err != nil {
		return nil, status.Error(codes.NotFound, "User not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid password")
	}

	isBanned, _ := s.Redis.SIsMember(ctx, "blacklist", user.ID).Result()
	if isBanned {
		return nil, status.Error(codes.PermissionDenied, "User is banned")
	}

	token, err := utils.GenerateToken(user, s.SecretKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate token")
	}

	return &users_v1.LoginResponse{
		Token:   token,
		Message: "Login successful",
	}, nil
}

func (s *PublicUserServiceServer) Revalidate(ctx context.Context, req *users_v1.RevalidateRequest) (*users_v1.RevalidateResponse, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(req.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.SecretKey), nil
	}, jwt.WithoutClaimsValidation())
	if err != nil || !token.Valid {
		return nil, status.Error(codes.Unauthenticated, "Invalid token")
	}

	isTokenBlacklisted, _ := s.Redis.SIsMember(ctx, "token_blacklist", req.Token).Result()
	if isTokenBlacklisted {
		return nil, status.Error(codes.Unauthenticated, "Token is blacklisted")
	}

	newClaims := &Claims{
		ID:   claims.ID,
		Role: claims.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
	newTokenString, err := newToken.SignedString([]byte(s.SecretKey))
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate new token")
	}

	return &users_v1.RevalidateResponse{
		Token:   newTokenString,
		Message: "Token revalidated successfully",
	}, nil
}

func (s *PublicUserServiceServer) Logout(ctx context.Context, req *users_v1.LogoutRequest) (*users_v1.LogoutResponse, error) {
	headers, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Headers are missing")
	}

	authHeaders := headers.Get("Authorization")
	if len(authHeaders) == 0 {
		return nil, status.Error(codes.Unauthenticated, "Authorization header is missing")
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, status.Error(codes.Unauthenticated, "Invalid authorization header format")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		return nil, status.Error(codes.Unauthenticated, "Token is missing")
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.SecretKey), nil
	})
	if err != nil || !token.Valid {
		return nil, status.Error(codes.Unauthenticated, "Invalid token")
	}

	ttl := time.Unix(claims.ExpiresAt, 0).Sub(time.Now())
	if ttl <= 0 {
		return &users_v1.LogoutResponse{Message: "Token already expired"}, nil
	}

	if err := s.Redis.SAdd(ctx, "token_blacklist", tokenString).Err(); err != nil {
		return nil, status.Error(codes.Internal, "Failed to blacklist token")
	}
	if err := s.Redis.Expire(ctx, "token_blacklist", ttl).Err(); err != nil {
		return nil, status.Error(codes.Internal, "Failed to set TTL")
	}

	return &users_v1.LogoutResponse{Message: "Logged out successfully"}, nil
}
