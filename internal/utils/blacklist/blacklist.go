package blacklist

import (
	"context"
	"time"

	"github.com/go-redis/redis/v8"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Blacklist interface {
	BanUser(ctx context.Context, userID string) error
	BanToken(ctx context.Context, token string) error
	CheckUser(ctx context.Context, userID string) error
	CheckToken(ctx context.Context, token string) error
	AddToken(ctx context.Context, token string, ttl time.Duration) error
}

type RedisBlacklist struct {
	client      *redis.Client
	userPrefix  string
	tokenPrefix string
}

func NewRedisBlacklist(client *redis.Client, userPrefix, tokenPrefix string) *RedisBlacklist {
	return &RedisBlacklist{
		client:      client,
		userPrefix:  userPrefix,
		tokenPrefix: tokenPrefix,
	}
}

func (b *RedisBlacklist) BanUser(ctx context.Context, userID string, ttl time.Duration) error {
	key := b.userPrefix + userID
	if err := b.client.Set(ctx, key, "user_banned", ttl).Err(); err != nil {
		return status.Error(codes.Internal, "Failed to ban user")
	}
	return nil
}

func (b *RedisBlacklist) BanToken(ctx context.Context, token string, ttl time.Duration) error {
	key := b.tokenPrefix + token
	if err := b.client.Set(ctx, key, "token_banned", ttl).Err(); err != nil {
		return status.Error(codes.Internal, "Failed to logout")
	}
	return nil
}

func (b *RedisBlacklist) CheckUser(ctx context.Context, userID string) error {
	key := b.userPrefix + userID
	_, err := b.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil
	} else if err != nil {
		return status.Error(codes.Internal, "Failed to check user blacklist: "+err.Error())
	}
	return status.Error(codes.PermissionDenied, "User is banned")
}

func (b *RedisBlacklist) CheckToken(ctx context.Context, token string) error {
	key := b.tokenPrefix + token
	_, err := b.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil
	} else if err != nil {
		return status.Error(codes.Internal, "Failed to check token blacklist: "+err.Error())
	}
	return status.Error(codes.PermissionDenied, "Token is blacklisted")
}

func (b *RedisBlacklist) AddToken(ctx context.Context, token string, ttl time.Duration) error {
	key := b.tokenPrefix + token
	if err := b.client.Set(ctx, key, "blacklisted", ttl).Err(); err != nil {
		return status.Error(codes.Internal, "Failed to blacklist token: "+err.Error())
	}
	return nil
}
