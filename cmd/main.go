package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"user_project/internal/domain"
	"user_project/internal/repository"
	grpcserver "user_project/internal/transport/grpc"
	"user_project/internal/utils"
	users_v1 "user_project/pkg/grpc/users.v1"

	"github.com/go-redis/redis/v8"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func selectiveRoleRequired(secretKey string, redisClient *redis.Client, adminMethods map[string]bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		tokenString, err := utils.ExtractTokenFromContext(ctx)
		if err != nil {
			return nil, err
		}

		claims, err := utils.ParseAndValidateToken(tokenString, secretKey)
		if err != nil {
			return nil, err
		}
		isBanned, _ := redisClient.SIsMember(ctx, "blacklist", claims.ID).Result()
		if isBanned {
			return nil, status.Error(codes.PermissionDenied, "User is banned")
		}
		ctx = context.WithValue(ctx, "userID", claims.ID)
		ctx = context.WithValue(ctx, "role", claims.Role)

		if adminMethods[info.FullMethod] {
			role, ok := ctx.Value("role").(string)
			if !ok || role != string(domain.ADMIN) {
				return nil, status.Error(codes.PermissionDenied, "Forbidden: admin role required")
			}
		}
		return handler(ctx, req)
	}
}

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

	redisClient := redis.NewClient(&redis.Options{Addr: redisAddr})
	_, err = redisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()

	userRepo := repository.NewUserRepository(db)
	secretKey = "your-secret-key"

	publicLis, _ := net.Listen("tcp", ":50054")
	publicSrv := grpc.NewServer()
	reflection.Register(publicSrv)
	users_v1.RegisterPublicUserServiceServer(publicSrv, grpcserver.NewPublicUserServiceServer(userRepo, redisClient, secretKey))
	go func() {
		log.Printf("Public server listening at %v", publicLis.Addr())
		if err := publicSrv.Serve(publicLis); err != nil {
			log.Fatalf("Failed to serve public: %v", err)
		}
	}()

	adminMethods := map[string]bool{
		"/users.v1.InternalUserService/AssignAdmin":    true,
		"/users.v1.InternalUserService/CreateEmployee": true,
		"/users.v1.InternalUserService/BanUser":        true,
	}
	internalLis, _ := net.Listen("tcp", ":50055")
	internalSrv := grpc.NewServer(
		grpc.UnaryInterceptor(selectiveRoleRequired(secretKey, redisClient, adminMethods)),
	)
	reflection.Register(internalSrv)
	users_v1.RegisterInternalUserServiceServer(internalSrv, grpcserver.NewInternalUserServiceServer(userRepo, redisClient, secretKey))
	log.Printf("Internal server listening at %v", internalLis.Addr())
	if err := internalSrv.Serve(internalLis); err != nil {
		log.Fatalf("Failed to serve internal: %v", err)
	}
}
