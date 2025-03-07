package grpc

import (
	v1 "user_project/pkg/grpc/users/v1"

	"gorm.io/gorm"
)

type PublicUsersServiceServer struct {
	v1.UnimplementedPublicUserServiceServer
	DB        *gorm.DB
	SecretKey string
}

type InternalServer struct {
	v1.UnimplementedInternalUserServiceServer
	DB        *gorm.DB
	Redis     *redis.Client
	SecretKey string
}
