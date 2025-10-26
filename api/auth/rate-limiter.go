package auth

import (
	"context"
	"fmt"
	"time"

	database "boge.dev/golang-api/db"
)

const (
	rateLimitWindow  = 15 * time.Minute
	maxLoginAttempts = 5
	lockoutDuration  = 30 * time.Minute

	loginAttemptsKey = "login_attempts:%s"
	accountLockedKey = "account_locked:%s"
	ipRateLimitKey   = "ip_rate_limit:%s"
)

type RateLimiter struct {
	maxAttempts     int
	window          time.Duration
	lockoutDuration time.Duration
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		maxAttempts:     maxLoginAttempts,
		window:          rateLimitWindow,
		lockoutDuration: lockoutDuration,
	}
}

func (rl *RateLimiter) CheckRateLimit(ctx context.Context, email string) error {
	lockedKey := fmt.Sprintf(accountLockedKey, email)
	locked, err := database.RDB.Client.Get(ctx, lockedKey).Result()
	if err == nil && locked == "1" {
		return ErrAccountLocked
	}

	attemptsKey := fmt.Sprintf(loginAttemptsKey, email)
	attemptsStr, err := database.RDB.Client.Get(ctx, attemptsKey).Int()
	if err != nil && err.Error() != "redis: nil" {
		return fmt.Errorf("rate limit check failed: %w", err)
	}

	if attemptsStr >= rl.maxAttempts {
		database.RDB.Client.Set(ctx, lockedKey, "1", rl.lockoutDuration)
		return ErrAccountLocked
	}

	return nil
}

func (rl *RateLimiter) RecordFailedAttempt(ctx context.Context, email string) error {
	attemptsKey := fmt.Sprintf(loginAttemptsKey, email)

	pipe := database.RDB.Client.Pipeline()
	pipe.Incr(ctx, attemptsKey)
	pipe.Expire(ctx, attemptsKey, rl.window)

	_, err := pipe.Exec(ctx)
	return err
}

func (rl *RateLimiter) ResetAttempts(ctx context.Context, email string) error {
	attemptsKey := fmt.Sprintf(loginAttemptsKey, email)
	lockedKey := fmt.Sprintf(accountLockedKey, email)

	pipe := database.RDB.Client.Pipeline()
	pipe.Del(ctx, attemptsKey)
	pipe.Del(ctx, lockedKey)

	_, err := pipe.Exec(ctx)
	return err
}

func (rl *RateLimiter) CheckIPRateLimit(ctx context.Context, ip string, maxRequests int, window time.Duration) error {
	key := fmt.Sprintf(ipRateLimitKey, ip)

	count, err := database.RDB.Client.Get(ctx, key).Int()
	if err != nil && err.Error() != "redis: nil" {
		return err
	}

	if count >= maxRequests {
		return ErrRateLimitExceeded
	}

	pipe := database.RDB.Client.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err = pipe.Exec(ctx)

	return err
}
