package auth

import (
	"context"
	"fmt"
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
		ip := "192.168.1.1"

		for i := 0; i < 5; i++ {
			err := limiter.CheckRateLimit(ctx, email, ip)
			assert.NoError(t, err, "Attempt %d should be allowed", i+1)

			limiter.RecordFailedAttempt(ctx, email, ip)
		}

		err := limiter.CheckRateLimit(ctx, email, ip)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAccountLocked, "Account should be locked after max attempts")
	})

	t.Run("WindowExpiry", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()
		email := "windowexpiry@example.com"
		ip := "192.168.1.2"

		limiter.RecordFailedAttempt(ctx, email, ip)
		limiter.RecordFailedAttempt(ctx, email, ip)

		err := limiter.CheckRateLimit(ctx, email, ip)
		assert.NoError(t, err, "Should be allowed, not enough attempts yet")

		// Record more attempts to trigger lock
		limiter.RecordFailedAttempt(ctx, email, ip)
		limiter.RecordFailedAttempt(ctx, email, ip)
		limiter.RecordFailedAttempt(ctx, email, ip)

		err = limiter.CheckRateLimit(ctx, email, ip)
		assert.Error(t, err)

		mr.FastForward(20 * time.Minute)

		err = limiter.CheckRateLimit(ctx, email, ip)
		assert.NoError(t, err, "Should be allowed after window expiry")
	})

	t.Run("ResetAfterSuccess", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()
		email := "reset@example.com"
		ip := "192.168.1.3"

		for i := 0; i < 4; i++ {
			limiter.RecordFailedAttempt(ctx, email, ip)
		}

		err := limiter.ResetAttempts(ctx, email, ip)
		require.NoError(t, err)

		err = limiter.CheckRateLimit(ctx, email, ip)
		assert.NoError(t, err, "Should be allowed after successful login")
	})

	t.Run("AccountLockout", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()
		email := "lockout@example.com"
		ip := "192.168.1.4"

		for i := 0; i < 5; i++ {
			limiter.RecordFailedAttempt(ctx, email, ip)
		}

		err := limiter.CheckRateLimit(ctx, email, ip)
		assert.ErrorIs(t, err, ErrAccountLocked)

		err = limiter.CheckRateLimit(ctx, email, ip)
		assert.Error(t, err, "Should still be locked during lockout period")

		time.Sleep(250 * time.Millisecond)

		limiter.ResetAttempts(ctx, email, ip)

		err = limiter.CheckRateLimit(ctx, email, ip)
		assert.NoError(t, err, "Should be allowed after reset")
	})

	t.Run("IPRateLimit", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()
		ip := "192.168.1.100"
		email := "iptest@example.com"

		// Test IP-based limiting by trying multiple accounts from same IP
		for i := 0; i < 20; i++ {
			testEmail := fmt.Sprintf("user%d@example.com", i)
			err := limiter.CheckRateLimit(ctx, testEmail, ip)
			assert.NoError(t, err, "Request %d should be allowed", i+1)
			limiter.RecordFailedAttempt(ctx, testEmail, ip)
		}

		// 21st attempt should be blocked
		err := limiter.CheckRateLimit(ctx, email, ip)
		assert.ErrorIs(t, err, ErrRateLimitExceeded, "Should be rate limited after 20 attempts")
	})

	t.Run("ConcurrentAttempts", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()
		email := "concurrent@example.com"
		ip := "192.168.1.200"

		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func() {
				limiter.RecordFailedAttempt(ctx, email, ip)
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		err := limiter.CheckRateLimit(ctx, email, ip)
		assert.Error(t, err, "Should be locked after concurrent attempts")
	})

	t.Run("DifferentUsers", func(t *testing.T) {
		limiter := NewRateLimiter()
		ctx := context.Background()

		for i := 0; i < 5; i++ {
			limiter.RecordFailedAttempt(ctx, "user1@example.com", "192.168.1.10")
		}

		err := limiter.CheckRateLimit(ctx, "user1@example.com", "192.168.1.10")
		assert.ErrorIs(t, err, ErrAccountLocked)

		err = limiter.CheckRateLimit(ctx, "user2@example.com", "192.168.1.11")
		assert.NoError(t, err, "Different user should not be affected")
	})
}
