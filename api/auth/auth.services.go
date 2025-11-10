package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"boge.dev/golang-api/api/user"
	"boge.dev/golang-api/constants"
	database "boge.dev/golang-api/db"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthService struct {
	DB          *gorm.DB
	UserService *user.UserService
	RateLimiter *RateLimiter
}

func NewAuthService() *AuthService {
	return &AuthService{
		DB:          database.DB.DB,
		UserService: user.NewUserService(),
		RateLimiter: NewRateLimiter(),
	}
}

func parseJWT(tokenString string) (map[string]interface{}, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New("JWT_SECRET environment variable not set")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, ErrTokenExpired
		}
	}

	return claims, nil
}

func createJWTToken(data JWTData, duration time.Duration) (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	var claimsMap map[string]interface{}
	if err := json.Unmarshal(b, &claimsMap); err != nil {
		return "", err
	}

	now := time.Now().Unix()
	if _, ok := claimsMap["exp"]; !ok {
		claimsMap["exp"] = now + int64(duration.Seconds())
	}
	if _, ok := claimsMap["iat"]; !ok {
		claimsMap["iat"] = now
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claimsMap))

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", errors.New("JWT_SECRET environment variable not set")
	}

	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", ErrInvalidToken
	}

	return signedToken, nil
}

func (s *AuthService) Login(dto LoginDTO) (*LoginResponse, error) {
	ctx := context.Background()
	if err := ValidateLoginDTO(dto); err != nil {
		return nil, err
	}

	// Get client IP from context (should be passed from controller)
	clientIP := dto.ClientIP
	if clientIP == "" {
		clientIP = "unknown"
	}

	if err := s.RateLimiter.CheckRateLimit(ctx, dto.Email, clientIP); err != nil {
		return nil, err
	}

	userData, err := s.UserService.GetUserByEmail(dto.Email)
	if err != nil {
		if recordErr := s.RateLimiter.RecordFailedAttempt(ctx, dto.Email, clientIP); recordErr != nil {
			// Log the error but don't fail the request
			// Consider adding proper logging here
			log.Printf("%s: failed to record a failed attempt", recordErr)
		}
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userData.Password), []byte(dto.Password)); err != nil {
		if recordErr := s.RateLimiter.RecordFailedAttempt(ctx, dto.Email, clientIP); recordErr != nil {
			// Log the error but don't fail the request
			log.Printf("%s: failed to record a failed attempt", recordErr)
		}
		return nil, ErrInvalidCredentials
	}

	if err := s.RateLimiter.ResetAttempts(ctx, dto.Email, clientIP); err != nil {
		// Log the error but don't fail the login
		// The user successfully authenticated, so we proceed
		log.Printf("%s: failed to reset rate limiter attempts", err)
	}

	authToken, err := createJWTToken(JWTData{
		ID:    userData.ID,
		Email: userData.Email,
		Role:  userData.Role,
	}, constants.MaxLoginTokenAge)
	if err != nil {
		return nil, err
	}
	refreshTokenJTI := uuid.New().String()
	refreshToken, err := createJWTToken(JWTData{
		ID:    userData.ID,
		Email: userData.Email,
		Role:  userData.Role,
		JTI:   refreshTokenJTI,
	}, constants.MaxRefreshTokenAge)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		AuthToken:    authToken,
		RefreshToken: refreshToken,
		RefreshJTI:   refreshTokenJTI,
		User:         userData,
	}, nil
}

func (s *AuthService) Logout(refreshToken string) error {
	ctx := context.Background()
	claims, err := parseJWT(refreshToken)
	if err != nil {
		return err
	}

	jtiVal, ok := claims["jti"]
	if !ok {
		return nil
	}
	jti, ok := jtiVal.(string)
	if !ok || jti == "" {
		return nil
	}

	expVal, ok := claims["exp"]
	if !ok {
		return database.RDB.Client.Set(ctx, fmt.Sprintf("refresh_blacklist:%s", jti), "1", 24*time.Hour).Err()
	}

	var expUnix int64
	switch v := expVal.(type) {
	case float64:
		expUnix = int64(v)
	case int64:
		expUnix = v
	case json.Number:
		n, _ := v.Int64()
		expUnix = n
	default:
		return errors.New("invalid exp claim")
	}

	ttl := time.Until(time.Unix(expUnix, 0))
	if ttl <= 0 {
		return nil
	}

	key := fmt.Sprintf("refresh_blacklist:%s", jti)
	return database.RDB.Client.Set(ctx, key, "1", ttl).Err()
}

func (s *AuthService) RefreshToken(refreshToken string) (*LoginResponse, error) {
	ctx := context.Background()
	claims, err := parseJWT(refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	jtiVal, ok := claims["jti"]
	if !ok {
		return nil, ErrMissingJTI
	}
	jti, ok := jtiVal.(string)
	if !ok || jti == "" {
		return nil, ErrInvalidJTI
	}

	blacklistKey := fmt.Sprintf("refresh_blacklist:%s", jti)
	exists, err := database.RDB.Client.SetNX(ctx, blacklistKey, "1", 0).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check blacklist: %w", err)
	}

	if !exists {
		return nil, ErrTokenRevoked
	}

	subVal := claims["sub"]
	emailVal := claims["email"]
	roleVal := claims["role"]

	var userID, email, role string
	var userData *user.User

	// Extract sub (user ID)
	if subVal != nil {
		switch v := subVal.(type) {
		case string:
			userID = v
		case float64:
			userID = fmt.Sprintf("%.0f", v)
		}
	}

	if emailVal != nil {
		email, _ = emailVal.(string)
	}
	if roleVal != nil {
		role, _ = roleVal.(string)
	}

	// Fetch user from database if we have a userID
	if userID != "" {
		var err error
		userData, err = s.UserService.GetUserByID(userID)
		if err != nil {
			return nil, ErrUserNotFound
		}
	} else {
		// If no userID, create a minimal user object from token claims
		userData = &user.User{}
		if email != "" {
			userData.Email = email
		}
		if role != "" {
			userData.Role = role
		}
	}

	expVal, ok := claims["exp"]
	if ok {
		var expUnix int64
		switch v := expVal.(type) {
		case float64:
			expUnix = int64(v)
		case int64:
			expUnix = v
		case json.Number:
			n, _ := v.Int64()
			expUnix = n
		default:
			return nil, fmt.Errorf("%w: invalid exp claim", ErrInvalidToken)
		}
		ttl := time.Until(time.Unix(expUnix, 0))
		if ttl > 0 {
			if err = database.RDB.Client.Set(ctx, blacklistKey, "1", ttl).Err(); err != nil {
				return nil, fmt.Errorf("failed to blacklist refresh token: %w", err)
			}
		}
	}

	authToken, err := createJWTToken(JWTData{
		ID:    userID,
		Email: email,
		Role:  role,
	}, constants.MaxLoginTokenAge)
	if err != nil {
		return nil, err
	}

	newJTI := uuid.New().String()
	newRefreshToken, err := createJWTToken(JWTData{
		ID:    userID,
		Email: email,
		Role:  role,
		JTI:   newJTI,
	}, constants.MaxRefreshTokenAge)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		AuthToken:    authToken,
		RefreshToken: newRefreshToken,
		RefreshJTI:   newJTI,
		User:         userData,
	}, nil
}
