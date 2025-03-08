package middleware

import (
	"context"
	"user_project/internal/domain"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func RoleRequiredMiddleware(adminMethods map[string]bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if adminMethods[info.FullMethod] {
			role, ok := ctx.Value("role").(string)
			if !ok {
				return nil, status.Error(codes.Internal, "Role not found in context")
			}
			if role == string(domain.USER) {
				return nil, status.Error(codes.PermissionDenied, "Forbidden: admin or employee role required")
			}
		}
		return handler(ctx, req)
	}
}
