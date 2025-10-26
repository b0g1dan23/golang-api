package auth

import (
	"context"
	"encoding/json"
	"errors"
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

	if err := s.RateLimiter.CheckRateLimit(ctx, dto.Email); err != nil {
		return nil, err
	}

	userData, err := s.UserService.GetUserByEmail(dto.Email)
	if err != nil {
		s.RateLimiter.RecordFailedAttempt(ctx, dto.Email)
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(userData.Password), []byte(dto.Password)); err != nil {
		s.RateLimiter.RecordFailedAttempt(ctx, dto.Email)
		return nil, ErrInvalidCredentials
	}

	s.RateLimiter.ResetAttempts(ctx, dto.Email)

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
