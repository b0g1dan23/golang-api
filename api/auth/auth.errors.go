package auth

import "errors"

var (
	ErrEmptyEmail         = errors.New("email cannot be empty")
	ErrEmptyPassword      = errors.New("password cannot be empty")
	ErrInvalidEmailFormat = errors.New("invalid email format")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenExpired       = errors.New("token has expired")
	ErrInvalidToken       = errors.New("invalid token")
	ErrDatabaseError      = errors.New("database error")
	ErrPasswordTooWeak    = errors.New("password does not meet security requirements")

	ErrAccountLocked     = errors.New("account temporarily locked due to too many failed attempts")
	ErrRateLimitExceeded = errors.New("rate limit exceeded, please try again later")
)
