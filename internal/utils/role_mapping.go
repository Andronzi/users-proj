package utils

import (
	"user_project/internal/domain"
	users_v1 "user_project/pkg/grpc/users.v1"
)

func GrpcToDomainRole(grpcRole users_v1.Role) domain.Role {
	switch grpcRole {
	case users_v1.Role_USER:
		return domain.USER
	case users_v1.Role_EMPLOYEE:
		return domain.EMPLOYEE
	case users_v1.Role_ADMIN:
		return domain.ADMIN
	default:
		return domain.USER
	}
}

func DomainToGrpcRole(domainRole domain.Role) users_v1.Role {
	switch domainRole {
	case domain.USER:
		return users_v1.Role_USER
	case domain.EMPLOYEE:
		return users_v1.Role_EMPLOYEE
	case domain.ADMIN:
		return users_v1.Role_ADMIN
	default:
		return users_v1.Role_USER
	}
}
