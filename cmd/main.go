package main

import (
	"log"
	"net"

	"google.golang.org/grpc"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(postgres.Open("host=localhost port=5432 user=postgres dbname=mydb password=secret"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	db.AutoMigrate(&User{})
	redisClient := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	secretKey := "your-secret-key"

	publicLis, _ := net.Listen("tcp", ":50051")
	publicSrv := grpc.NewServer()
	pb.RegisterPublicUserServiceServer(publicSrv, &PublicUsersServiceServer{DB: db, SecretKey: secretKey})
	go func() {
		log.Printf("Public server listening at %v", publicLis.Addr())
		if err := publicSrv.Serve(publicLis); err != nil {
			log.Fatalf("Failed to serve public: %v", err)
		}
	}()

	// Внутренний сервер с интерцептором
	adminMethods := map[string]bool{
		"/user.InternalUserService/AssignAdmin":    true,
		"/user.InternalUserService/CreateEmployee": true,
		"/user.InternalUserService/BanUser":        true,
	}
	internalLis, _ := net.Listen("tcp", ":50052")
	internalSrv := grpc.NewServer(
		grpc.UnaryInterceptor(selectiveRoleRequired(secretKey, redisClient, adminMethods)),
	)
	pb.RegisterInternalUserServiceServer(internalSrv, &InternalServer{DB: db, Redis: redisClient, SecretKey: secretKey})
	log.Printf("Internal server listening at %v", internalLis.Addr())
	if err := internalSrv.Serve(internalLis); err != nil {
		log.Fatalf("Failed to serve internal: %v", err)
	}
}
