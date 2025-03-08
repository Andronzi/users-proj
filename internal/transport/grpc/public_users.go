package grpc

import (
	"context"
	"user_project/internal/domain"
	"user_project/internal/repository"
	"user_project/internal/utils"
	"user_project/internal/utils/blacklist"
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
	Repo           *repository.UserRepository
	Redis          *redis.Client
	RedisBlacklist *blacklist.RedisBlacklist
	SecretKey      string
}

func NewPublicUserServiceServer(repo *repository.UserRepository, redis *redis.Client, secretKey string) *PublicUserServiceServer {
	return &PublicUserServiceServer{
		Repo:           repo,
		Redis:          redis,
		RedisBlacklist: blacklist.NewRedisBlacklist(redis, blacklist.UserBlackList, blacklist.TokenBlackList),
		SecretKey:      secretKey,
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

	token, err := utils.GenerateToken(utils.TokenParams{ID: user.ID, Role: string(user.Role)}, s.SecretKey)
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

	if err := s.RedisBlacklist.CheckUser(ctx, user.ID); err != nil {
		return nil, err
	}

	token, err := utils.GenerateToken(utils.TokenParams{ID: user.ID, Role: string(user.Role)}, s.SecretKey)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to generate token")
	}

	return &users_v1.LoginResponse{
		Token:   token,
		Message: "Login successful",
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
