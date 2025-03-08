package utils

import (
	"context"
	"strings"
	"time"
	"user_project/internal/domain"

	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type Claims struct {
	ID   string `json:"id"`
	Role string `json:"role"`
	jwt.StandardClaims
}

func GenerateToken(user *domain.User, secretKey string) (string, error) {
	claims := &Claims{
		ID:   user.ID,
		Role: string(user.Role),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func ParseAndValidateToken(tokenString string, secretKey string, options ...jwt.ParserOption) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	}, options...)

	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Token have errors")
	}

	if err != nil || !token.Valid {
		return nil, status.Error(codes.Unauthenticated, "Invalid token")
	}

	return claims, nil
}

func ExtractTokenFromContext(ctx context.Context) (string, error) {
	headers, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		return "", status.Error(codes.Unauthenticated, "Headers are missing")
	}

	authHeaders := headers.Get("Authorization")
	if len(authHeaders) == 0 {
		return "", status.Error(codes.Unauthenticated, "Authorization header is missing")
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", status.Error(codes.Unauthenticated, "Invalid authorization header format")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		return "", status.Error(codes.Unauthenticated, "Token is missing")
	}

	return tokenString, nil
}
