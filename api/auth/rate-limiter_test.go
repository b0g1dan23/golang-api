package auth

import (
	"context"
	"testing"
	"time"

	"boge.dev/golang-api/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter(t *testing.T) {
	testutils.SetupTestConfig(t)
	testutils.SetupTestDB(t)
	mr := testutils.SetupTestRedis(t)
	defer mr.Close()

	t.Run("MaxAttempts", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()
		email := "maxattempts@example.com"

		for i := 0; i < maxLoginAttempts; i++ {
			err := limiter.CheckRateLimit(ctx, email)
			assert.NoError(t, err, "Attempt %d should be allowed", i+1)

			limiter.RecordFailedAttempt(ctx, email)
		}

		err := limiter.CheckRateLimit(ctx, email)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAccountLocked, "Account should be locked after max attempts")
	})

	t.Run("WindowExpiry", func(t *testing.T) {
		limiter := &RateLimiter{
			maxAttempts:     2,
			window:          2 * time.Second,
			lockoutDuration: 2 * time.Second,
		}

		ctx := context.Background()
		email := "windowexpiry@example.com"

		limiter.RecordFailedAttempt(ctx, email)
		limiter.RecordFailedAttempt(ctx, email)

		err := limiter.CheckRateLimit(ctx, email)
		assert.Error(t, err)

		mr.FastForward(3 * time.Second)

		err = limiter.CheckRateLimit(ctx, email)
		assert.NoError(t, err, "Should be allowed after window expiry")
	})

	t.Run("ResetAfterSuccess", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()
		email := "reset@example.com"

		for i := 0; i < 4; i++ {
			limiter.RecordFailedAttempt(ctx, email)
		}

		err := limiter.ResetAttempts(ctx, email)
		require.NoError(t, err)

		err = limiter.CheckRateLimit(ctx, email)
		assert.NoError(t, err, "Should be allowed after successful login")
	})

	t.Run("AccountLockout", func(t *testing.T) {
		limiter := &RateLimiter{
			maxAttempts:     3,
			window:          1 * time.Minute,
			lockoutDuration: 200 * time.Millisecond,
		}

		ctx := context.Background()
		email := "lockout@example.com"

		for i := 0; i < 3; i++ {
			limiter.RecordFailedAttempt(ctx, email)
		}

		err := limiter.CheckRateLimit(ctx, email)
		assert.ErrorIs(t, err, ErrAccountLocked)

		err = limiter.CheckRateLimit(ctx, email)
		assert.Error(t, err, "Should still be locked during lockout period")

		time.Sleep(250 * time.Millisecond)

		limiter.ResetAttempts(ctx, email)

		err = limiter.CheckRateLimit(ctx, email)
		assert.NoError(t, err, "Should be allowed after lockout expiry")
	})

	t.Run("IPRateLimit", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()
		ip := "192.168.1.100"

		for i := 0; i < 100; i++ {
			err := limiter.CheckIPRateLimit(ctx, ip, 100, 1*time.Minute)
			assert.NoError(t, err, "Request %d should be allowed", i+1)
		}

		err := limiter.CheckIPRateLimit(ctx, ip, 100, 1*time.Minute)
		assert.ErrorIs(t, err, ErrRateLimitExceeded)
	})

	t.Run("ConcurrentAttempts", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()
		email := "concurrent@example.com"

		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				limiter.RecordFailedAttempt(ctx, email)
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		err := limiter.CheckRateLimit(ctx, email)
		assert.ErrorIs(t, err, ErrAccountLocked, "Should be locked after concurrent attempts")
	})

	t.Run("DifferentUsers", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()

		for i := 0; i < 5; i++ {
			limiter.RecordFailedAttempt(ctx, "user1@example.com")
		}

		err := limiter.CheckRateLimit(ctx, "user1@example.com")
		assert.ErrorIs(t, err, ErrAccountLocked)

		err = limiter.CheckRateLimit(ctx, "user2@example.com")
		assert.NoError(t, err, "Different user should not be affected")
	})
}
