package middleware

import (
	"context"
	"user_project/internal/utils"
	"user_project/internal/utils/blacklist"

	"google.golang.org/grpc"
)

func BlacklistMiddleware(secretKey string, blacklist *blacklist.RedisBlacklist) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		tokenString, err := utils.ExtractTokenFromContext(ctx)
		if err != nil {
			return nil, err
		}

		claims, err := utils.ParseAndValidateToken(tokenString, secretKey)
		if err != nil {
			return nil, err
		}

		if err := blacklist.CheckUser(ctx, claims.ID); err != nil {
			return nil, err
		}

		if err := blacklist.CheckToken(ctx, tokenString); err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, "userID", claims.ID)
		ctx = context.WithValue(ctx, "role", claims.Role)

		return handler(ctx, req)
	}
}
