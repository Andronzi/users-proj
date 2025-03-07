package grpc

import (
	"context"
	"time"
	"user_project/internal/domain"
	"user_project/internal/repository"
	users_v1 "user_project/pkg/grpc/users.v1"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
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
	exists, err := s.Repo.ExistsByUsernameOrEmail(ctx, req.Username, req.Email)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to check user existence")
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "Username or email already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to hash password")
	}

	user := &domain.User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
		Role:     "user",
	}
	if err := s.Repo.Create(ctx, user); err != nil {
		return nil, status.Error(codes.Internal, "Failed to create user")
	}

	claims := &Claims{
		ID:   user.ID,
		Role: user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.SecretKey))
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate token")
	}

	return &users_v1.RegisterResponse{
		Message: "User created successfully",
		Token:   tokenString,
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

	claims := &Claims{
		ID:   user.ID,
		Role: user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.SecretKey))
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate token")
	}

	return &users_v1.LoginResponse{
		Token:   tokenString,
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
