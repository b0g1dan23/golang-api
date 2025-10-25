package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/redis/go-redis/v9"
)

type RedisInstance struct {
	Client *redis.Client
}

var (
	RDB  *RedisInstance
	once sync.Once
	ctx  = context.Background()
)

func InitializeRedis() {
	once.Do(func() {
		client := redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT")),
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       0,
		})

		if err := client.Ping(ctx).Err(); err != nil {
			fmt.Println("Failed to connect to Redis:", err)
		}

		RDB = &RedisInstance{client}
		log.Println("Connected to Redis")
	})
}

func GetRedis() *redis.Client {
	if RDB == nil || RDB.Client == nil {
		log.Fatal("Redis is not initialized, please call InitializeRedis() first")
	}
	return RDB.Client
}
