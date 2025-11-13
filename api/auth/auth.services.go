package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"boge.dev/golang-api/api/user"
	"boge.dev/golang-api/constants"
	database "boge.dev/golang-api/db"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
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

func parseJWT(tokenString string) (*JWTData, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New("JWT_SECRET environment variable not set")
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTData{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTData)
	if !ok {
		return nil, ErrInvalidToken
	}

	if exp, err := claims.GetExpirationTime(); err != nil {
		if exp.Before(time.Now()) {
			return nil, ErrTokenExpired
		}
	}

	return claims, nil
}

func createJWTToken(data JWTData, duration time.Duration) (string, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return "", errors.New("JWT_SECRET environment variable not set")
	}

	now := time.Now()

	data.IssuedAt = jwt.NewNumericDate(now)
	data.ExpiresAt = jwt.NewNumericDate(now.Add(duration))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, data)

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

func (s *AuthService) LoginOAuthUser(dto OAuthLoginDTO) (*LoginResponse, error) {
	if err := ValidateOAuthLoginDTO(dto); err != nil {
		return nil, err
	}

	// Get or create user
	userData, err := s.UserService.GetUserByEmail(dto.Email)
	if err != nil {
		// User doesn't exist, create new user from OAuth data
		newUser := &user.User{
			FirstName: dto.FirstName,
			LastName:  dto.LastName,
			Email:     dto.Email,
			Role:      user.RoleUser,
			Password:  "", // No password for OAuth users
		}

		userData, err = s.UserService.CreateUser(newUser)
		if err != nil {
			return nil, fmt.Errorf("failed to create OAuth user: %w", err)
		}
	}

	// Generate JWT tokens
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
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	jti := claims.JTI
	if jti == "" {
		return fmt.Errorf("missing jti in refresh token")
	}

	expVal, _ := claims.GetExpirationTime()
	var ttl time.Duration

	if expVal == nil || expVal.Time.IsZero() {
		ttl = 24 * time.Hour
	} else {
		ttl = time.Until(expVal.Time)
		if ttl <= 0 {
			return nil
		}
	}

	key := fmt.Sprintf("refresh_blacklist:%s", jti)
	err = database.RDB.Client.Set(ctx, key, "1", ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set redis key: %w", err)
	}

	return nil
}

func (s *AuthService) RefreshToken(refreshToken string) (*LoginResponse, error) {
	ctx := context.Background()
	claims, err := parseJWT(refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	jti := claims.JTI

	if jti == "" {
		return nil, ErrMissingJTI
	}

	blacklistKey := fmt.Sprintf("refresh_blacklist:%s", jti)
	exists, err := database.RDB.Client.SetNX(ctx, blacklistKey, "1", 0).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check blacklist: %w", err)
	}

	if !exists {
		return nil, ErrTokenRevoked
	}

	var ttl time.Duration
	expVal, _ := claims.GetExpirationTime()
	if expVal != nil && !expVal.Time.IsZero() {
		ttl = time.Until(expVal.Time)
		if ttl < 0 {
			ttl = 0
		}
	} else {
		ttl = 24 * time.Hour
	}

	if err = database.RDB.Client.Set(ctx, blacklistKey, "1", ttl).Err(); err != nil {
		return nil, fmt.Errorf("failed to blacklist refresh token: %w", err)
	}

	var userData *user.User
	userID := claims.ID
	if userID != "" {
		userData, err = s.UserService.GetUserByID(userID)
		if err != nil {
			return nil, ErrUserNotFound
		}
	}

	email := claims.Email
	role := claims.Role

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

func MapGoogleUserToUser(userInfo map[string]interface{}) (*user.User, error) {
	givenName, _ := userInfo["given_name"].(string)
	familyName, _ := userInfo["family_name"].(string)
	email, _ := userInfo["email"].(string)

	return &user.User{
		FirstName: strings.TrimSpace(givenName),
		LastName:  strings.TrimSpace(familyName),
		Email:     strings.TrimSpace(email),
		Role:      user.RoleUser,
		Password:  "", // OAuth users have empty passwords and can only authenticate via OAuth
	}, nil
}

func (s *AuthService) ExchangeCodeAndGetUser(code string, oauthConfig *oauth2.Config) (*user.User, error) {
	token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Println("Code exchange failed:", err)
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Println("Failed to get user info:", err)
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Failed to close response body: %v", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: unexpected status %d", resp.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		log.Println("Failed to parse user info:", err)
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	user, err := MapGoogleUserToUser(userInfo)
	if err != nil {
		return nil, err
	}

	if user.Email == "" {
		return nil, fmt.Errorf("email is required from Google OAuth")
	}

	exists, err := s.UserService.GetUserByEmail(user.Email)
	if err == nil && exists != nil {
		return exists, nil
	}

	return s.UserService.CreateUser(user)
}
