package utils

import (
	"time"
	"user_project/internal/domain"

	"github.com/golang-jwt/jwt/v4"
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
