package constants

import "time"

const (
	MaxLoginTokenAge   = 24 * time.Hour       // 1 day
	MaxRefreshTokenAge = 7 * MaxLoginTokenAge // 7 days
	ForgotPWTokenTTL   = 15 * time.Minute
)
