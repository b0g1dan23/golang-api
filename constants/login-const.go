package constants

import "time"

const (
	MaxLoginTokenAge   = 24 * time.Hour       // 1 day in nanoseconds
	MaxRefreshTokenAge = 7 * MaxLoginTokenAge // 7 days in nanoseconds
)
