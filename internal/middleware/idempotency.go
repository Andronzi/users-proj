package middleware

import (
	"context"
	"os"
	"time"

	"github.com/Andronzi/credit-origination/pkg/logger"
	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type RedisCache struct {
	client *redis.Client
}

func NewRedisCache(addr string) *RedisCache {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: os.Getenv("REDIS_PASSWORD"),
	})
	return &RedisCache{client: rdb}
}

func (c *RedisCache) GetBytes(key string) ([]byte, bool) {
	val, err := c.client.Get(context.Background(), key).Bytes()
	if err == redis.Nil {
		return nil, false
	} else if err != nil {
		logger.Logger.Error("Redis get error", zap.Error(err))
		return nil, false
	}
	return val, true
}

func (c *RedisCache) SetBytes(key string, value []byte, ttl time.Duration) {
	err := c.client.Set(context.Background(), key, value, ttl).Err()
	if err != nil {
		logger.Logger.Error("Redis set error", zap.Error(err))
	}
}

var idempotencyCache = NewRedisCache(os.Getenv("REDIS_ADDR"))

func IdempotencyInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "metadata is required")
	}

	keys := md.Get("Idempotency-key")
	if len(keys) == 0 {
		return handler(ctx, req)
	}
	key := keys[0]

	logger.Logger.Info("Get idempotency key", zap.String("key", key))

	if cached, ok := idempotencyCache.GetBytes(key); ok {
		logger.Logger.Info("Returning cached response", zap.String("key", key))

		var anyResp anypb.Any
		if err := proto.Unmarshal(cached, &anyResp); err != nil {
			logger.Logger.Error("Failed to unmarshal Any response", zap.Error(err))
			return handler(ctx, req)
		}

		resp, err := anyResp.UnmarshalNew()
		if err != nil {
			logger.Logger.Error("Failed to unpack Any response", zap.Error(err))
			return handler(ctx, req)
		}

		return resp, nil
	}

	res, err := handler(ctx, req)
	if err == nil {
		anyRes, err := anypb.New(res.(proto.Message))
		if err != nil {
			logger.Logger.Error("Failed to pack response to Any", zap.Error(err))
			return res, nil
		}

		data, err := proto.Marshal(anyRes)
		if err != nil {
			logger.Logger.Error("Failed to marshal Any response", zap.Error(err))
			return res, nil
		}

		idempotencyCache.SetBytes(key, data, 24*time.Hour)
		logger.Logger.Info("Successfully set idempotency data by key", zap.String("key", key))
	}

	return res, err
}
