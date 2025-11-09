package auth

import (
	"context"
	"fmt"
	"time"

	database "boge.dev/golang-api/db"
)

const (
	// Email-based limits (softer - to prevent account lockout attacks)
	emailRateLimitWindow = 15 * time.Minute
	maxEmailAttempts     = 10               // Higher threshold for email
	emailLockoutDuration = 15 * time.Minute // Shorter lockout

	// IP-based limits (stricter - to prevent brute force)
	ipRateLimitWindow = 15 * time.Minute
	maxIPAttempts     = 20 // Can try multiple accounts
	ipLockoutDuration = 30 * time.Minute

	// Combined (email + IP) limits (strictest)
	maxEmailIPAttempts = 5 // Same email from same IP

	loginAttemptsKey   = "login_attempts:%s"       // email
	accountLockedKey   = "account_locked:%s"       // email
	ipAttemptsKey      = "ip_attempts:%s"          // IP
	ipLockedKey        = "ip_locked:%s"            // IP
	emailIPAttemptsKey = "email_ip_attempts:%s:%s" // email:IP
)

type RateLimiter struct {
	emailRateLimitWindow time.Duration
	maxEmailAttempts     int
	emailLockoutDuration time.Duration

	ipRateLimitWindow time.Duration
	maxIPAttempts     int
	ipLockoutDuration time.Duration

	maxEmailIPAttempts int
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		emailRateLimitWindow: emailRateLimitWindow,
		maxEmailAttempts:     maxEmailAttempts,
		emailLockoutDuration: emailLockoutDuration,
		ipRateLimitWindow:    ipRateLimitWindow,
		maxIPAttempts:        maxIPAttempts,
		ipLockoutDuration:    ipLockoutDuration,
		maxEmailIPAttempts:   maxEmailIPAttempts,
	}
}

// CheckRateLimit checks both email and IP-based rate limits
// This prevents account lockout attacks while still protecting against brute force
func (rl *RateLimiter) CheckRateLimit(ctx context.Context, email string, ip string) error {
	// Check if email is locked (softer limit)
	emailLockedKey := fmt.Sprintf(accountLockedKey, email)
	locked, err := database.RDB.Client.Get(ctx, emailLockedKey).Result()
	if err == nil && locked == "1" {
		return ErrAccountLocked
	}

	// Check if IP is locked (stricter limit)
	ipLockedKey := fmt.Sprintf(ipLockedKey, ip)
	ipLocked, err := database.RDB.Client.Get(ctx, ipLockedKey).Result()
	if err == nil && ipLocked == "1" {
		return ErrRateLimitExceeded
	}

	// Check email attempts
	emailAttemptsKey := fmt.Sprintf(loginAttemptsKey, email)
	emailAttempts, _ := database.RDB.Client.Get(ctx, emailAttemptsKey).Int()

	// Check IP attempts
	ipAttemptsKeyStr := fmt.Sprintf(ipAttemptsKey, ip)
	ipAttempts, _ := database.RDB.Client.Get(ctx, ipAttemptsKeyStr).Int()

	// Check combined email+IP attempts (strictest)
	emailIPKey := fmt.Sprintf(emailIPAttemptsKey, email, ip)
	emailIPAttempts, _ := database.RDB.Client.Get(ctx, emailIPKey).Int()

	// Lock if too many attempts from same email+IP combination
	if emailIPAttempts >= maxEmailIPAttempts {
		if err := database.RDB.Client.Set(ctx, emailLockedKey, "1", emailLockoutDuration).Err(); err != nil {
			return fmt.Errorf("failed to set email lockout: %w", err)
		}
		return ErrAccountLocked
	}

	// Lock if too many attempts for this email (from any IP)
	if emailAttempts >= maxEmailAttempts {
		if err := database.RDB.Client.Set(ctx, emailLockedKey, "1", emailLockoutDuration).Err(); err != nil {
			return fmt.Errorf("failed to set email lockout: %w", err)
		}
		return ErrAccountLocked
	}

	// Lock if too many attempts from this IP (trying multiple accounts)
	if ipAttempts >= maxIPAttempts {
		if err := database.RDB.Client.Set(ctx, ipLockedKey, "1", ipLockoutDuration).Err(); err != nil {
			return fmt.Errorf("failed to set IP lockout: %w", err)
		}
		return ErrRateLimitExceeded
	}

	return nil
}

// RecordFailedAttempt records a failed login attempt for both email and IP
func (rl *RateLimiter) RecordFailedAttempt(ctx context.Context, email string, ip string) error {
	emailAttemptsKey := fmt.Sprintf(loginAttemptsKey, email)
	ipAttemptsKeyStr := fmt.Sprintf(ipAttemptsKey, ip)
	emailIPKey := fmt.Sprintf(emailIPAttemptsKey, email, ip)

	pipe := database.RDB.Client.Pipeline()

	// Increment email attempts
	pipe.Incr(ctx, emailAttemptsKey)
	pipe.Expire(ctx, emailAttemptsKey, emailRateLimitWindow)

	// Increment IP attempts
	pipe.Incr(ctx, ipAttemptsKeyStr)
	pipe.Expire(ctx, ipAttemptsKeyStr, ipRateLimitWindow)

	// Increment email+IP attempts
	pipe.Incr(ctx, emailIPKey)
	pipe.Expire(ctx, emailIPKey, emailRateLimitWindow)

	_, err := pipe.Exec(ctx)
	return err
}

// ResetAttempts clears all attempts for email and IP after successful login
func (rl *RateLimiter) ResetAttempts(ctx context.Context, email string, ip string) error {
	emailAttemptsKey := fmt.Sprintf(loginAttemptsKey, email)
	emailLockedKey := fmt.Sprintf(accountLockedKey, email)
	ipAttemptsKeyStr := fmt.Sprintf(ipAttemptsKey, ip)
	ipLockedKey := fmt.Sprintf(ipLockedKey, ip)
	emailIPKey := fmt.Sprintf(emailIPAttemptsKey, email, ip)

	pipe := database.RDB.Client.Pipeline()
	pipe.Del(ctx, emailAttemptsKey)
	pipe.Del(ctx, emailLockedKey)
	pipe.Del(ctx, ipAttemptsKeyStr)
	pipe.Del(ctx, ipLockedKey)
	pipe.Del(ctx, emailIPKey)

	_, err := pipe.Exec(ctx)
	return err
}

// GetRemainingAttempts returns info about remaining attempts (for debugging/logging)
func (rl *RateLimiter) GetRemainingAttempts(ctx context.Context, email string, ip string) map[string]int {
	emailAttemptsKey := fmt.Sprintf(loginAttemptsKey, email)
	ipAttemptsKeyStr := fmt.Sprintf(ipAttemptsKey, ip)
	emailIPKey := fmt.Sprintf(emailIPAttemptsKey, email, ip)

	emailAttempts, _ := database.RDB.Client.Get(ctx, emailAttemptsKey).Int()
	ipAttempts, _ := database.RDB.Client.Get(ctx, ipAttemptsKeyStr).Int()
	emailIPAttempts, _ := database.RDB.Client.Get(ctx, emailIPKey).Int()

	return map[string]int{
		"email_attempts":    maxEmailAttempts - emailAttempts,
		"ip_attempts":       maxIPAttempts - ipAttempts,
		"email_ip_attempts": maxEmailIPAttempts - emailIPAttempts,
	}
}
