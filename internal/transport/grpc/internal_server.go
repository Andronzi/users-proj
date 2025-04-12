package grpc

import (
	"context"
	"time"
	"user_project/internal/domain"
	"user_project/internal/repository"
	"user_project/internal/utils"
	"user_project/internal/utils/blacklist"
	users_v1 "user_project/pkg/grpc/users.v1"

	"github.com/go-redis/redis/v8"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type InternalUserServiceServer struct {
	users_v1.UnimplementedInternalUserServiceServer
	Repo           *repository.UserRepository
	Redis          *redis.Client
	RedisBlacklist *blacklist.RedisBlacklist
	SecretKey      string
}

func NewInternalUserServiceServer(repo *repository.UserRepository, redis *redis.Client, redisBlacklist *blacklist.RedisBlacklist, secretKey string) *InternalUserServiceServer {
	return &InternalUserServiceServer{
		Repo:           repo,
		Redis:          redis,
		RedisBlacklist: redisBlacklist,
		SecretKey:      secretKey,
	}
}

func (s *InternalUserServiceServer) GetProfile(ctx context.Context, req *users_v1.GetProfileRequest) (*users_v1.GetProfileResponse, error) {
	userID, ok := ctx.Value("userID").(string)
	if !ok {
		return nil, status.Error(codes.Internal, "User ID not found in context")
	}

	user, err := s.Repo.FindByID(ctx, userID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "User not found")
	}

	return &users_v1.GetProfileResponse{
		Id:    user.ID,
		Email: user.Email,
		Role:  utils.DomainToGrpcRole(user.Role),
	}, nil
}

func (s *InternalUserServiceServer) AssignAdmin(ctx context.Context, req *users_v1.AssignAdminRequest) (*users_v1.AssignAdminResponse, error) {
	user, err := s.Repo.FindByID(ctx, req.UserId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "User not found")
	}

	user.Role = utils.GrpcToDomainRole(users_v1.Role_ADMIN)
	if err := s.Repo.Update(ctx, user); err != nil {
		return nil, status.Error(codes.Internal, "Failed to update user")
	}

	return &users_v1.AssignAdminResponse{Message: "Admin assigned successfully"}, nil
}

func (s *InternalUserServiceServer) CreateEmployee(ctx context.Context, req *users_v1.CreateEmployeeRequest) (*users_v1.CreateEmployeeResponse, error) {
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
		Role:     utils.GrpcToDomainRole(users_v1.Role_EMPLOYEE),
	}
	if err := s.Repo.Create(ctx, user); err != nil {
		return nil, status.Error(codes.Internal, "Failed to create employee")
	}

	return &users_v1.CreateEmployeeResponse{
		Message: "Employee created successfully",
		UserId:  user.ID,
	}, nil
}

func (s *InternalUserServiceServer) CreateUser(ctx context.Context, req *users_v1.CreateUserRequest) (*users_v1.CreateUserResponse, error) {
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
		Role:     utils.GrpcToDomainRole(users_v1.Role_USER),
	}
	if err := s.Repo.Create(ctx, user); err != nil {
		return nil, status.Error(codes.Internal, "Failed to create user")
	}

	return &users_v1.CreateUserResponse{
		Message: "User created successfully",
		UserId:  user.ID,
	}, nil
}

func (s *InternalUserServiceServer) BanUser(ctx context.Context, req *users_v1.BanUserRequest) (*users_v1.BanUserResponse, error) {
	user, err := s.Repo.FindByID(ctx, req.UserId)
	if err != nil {
		return nil, status.Error(codes.NotFound, "User not found")
	}

	if err := s.RedisBlacklist.BanUser(ctx, user.ID, time.Hour); err != nil {
		return nil, err
	}

	return &users_v1.BanUserResponse{Message: "User banned successfully"}, nil
}

func (s *InternalUserServiceServer) Authorize(ctx context.Context, req *users_v1.AuthorizeRequest) (*users_v1.AuthorizeResponse, error) {
	tokenString, err := utils.ExtractTokenFromContext(ctx)
	if err != nil {
		return nil, err
	}

	claims, err := utils.ParseAndValidateToken(tokenString, s.SecretKey)
	if err != nil {
		return nil, err
	}

	return &users_v1.AuthorizeResponse{
		IsValid: true,
		UserId:  claims.ID,
		Role:    users_v1.Role(users_v1.Role_value[claims.Role]),
		Message: "Successful authorized",
	}, nil
}

func (s *InternalUserServiceServer) ListUsers(ctx context.Context, req *users_v1.ListUsersRequest) (*users_v1.ListUsersResponse, error) {
	users, total, err := s.Repo.ListUsers(ctx, int(req.Page), int(req.PageSize), req.EmailFilter)
	if err != nil {
		return nil, status.Error(codes.Internal, "Failed to get users")
	}

	pbUsers := make([]*users_v1.User, len(users))
	for i, user := range users {
		pbUsers[i] = &users_v1.User{
			Id:    user.ID,
			Email: user.Email,
			Role:  utils.DomainToGrpcRole(user.Role),
		}
	}

	return &users_v1.ListUsersResponse{
		Users: pbUsers,
		Total: int32(total),
	}, nil
}
