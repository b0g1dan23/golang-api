package auth

import (
	"os"
	"testing"
	"time"

	database "boge.dev/golang-api/db"
	"boge.dev/golang-api/utils/testutils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testEmail    = "test@example.com"
	testPassword = "TestPassword123*"
)

func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}

func TestCreateJWTToken(t *testing.T) {
	testutils.SetupTestConfig(t)

	t.Run("Success", func(t *testing.T) {
		randUUID := uuid.New()
		data := JWTData{
			ID:    "123",
			Role:  "admin",
			Email: testEmail,
			JTI:   randUUID.String(),
		}

		token, err := createJWTToken(data, time.Hour)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		secret := os.Getenv("JWT_SECRET")
		err = testutils.ValidateJWTSecret(secret)
		assert.NoError(t, err, "JWT secret should be cryptographically secure")
	})

	t.Run("NoSecret", func(t *testing.T) {
		os.Unsetenv("JWT_SECRET")
		t.Cleanup(func() {
			testutils.RestoreTestJWTSecret(t)
		})

		randUUID := uuid.New()
		data := JWTData{
			ID:    "123",
			Role:  "admin",
			Email: testEmail,
			JTI:   randUUID.String(),
		}

		token, err := createJWTToken(data, time.Hour)
		assert.Error(t, err)
		assert.Equal(t, "", token)
		assert.Equal(t, "JWT_SECRET environment variable not set", err.Error())
	})

	t.Run("WeakSecret", func(t *testing.T) {
		weakSecrets := []string{
			"secret",
			"test",
			"password",
			"12345678",
			"short",
		}

		for _, weak := range weakSecrets {
			t.Run(weak, func(t *testing.T) {
				err := testutils.ValidateJWTSecret(weak)
				assert.Error(t, err, "Expected error for weak secret: %s", weak)
			})
		}
	})

	t.Run("EmptyData", func(t *testing.T) {
		data := JWTData{}

		token, err := createJWTToken(data, time.Hour)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("ZeroDuration", func(t *testing.T) {
		randUUID := uuid.New()
		data := JWTData{
			ID:    "123",
			Role:  "admin",
			Email: testEmail,
			JTI:   randUUID.String(),
		}

		token, err := createJWTToken(data, 0)
		assert.NoError(t, err, "Token creation should succeed even with zero duration")
		assert.NotEmpty(t, token)

		claims, err := testutils.ParseJWTClaimsAllowExpired(t, token)
		require.NoError(t, err, "Should be able to parse expired token")

		exp, expOk := claims["exp"].(float64)
		iat, iatOk := claims["iat"].(float64)

		assert.True(t, expOk, "exp claim should exist")
		assert.True(t, iatOk, "iat claim should exist")
		assert.Equal(t, exp, iat, "exp should equal iat for zero duration")

		_, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		assert.Error(t, err, "Token with zero duration should be expired")
		assert.Contains(t, err.Error(), "expired", "Error should mention token expiration")
	})

	t.Run("NegativeDuration", func(t *testing.T) {
		data := JWTData{
			ID:    "123",
			Role:  "admin",
			Email: testEmail,
		}

		token, err := createJWTToken(data, -1*time.Hour)
		assert.NoError(t, err, "Token creation should succeed")
		assert.NotEmpty(t, token)

		_, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		assert.Error(t, err, "Negative duration token should be expired")
	})

	t.Run("LongDuration", func(t *testing.T) {
		data := JWTData{
			ID:    "123",
			Role:  "admin",
			Email: testEmail,
		}

		token, err := createJWTToken(data, 365*24*time.Hour) // 1 year
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		claims := testutils.ParseJWTClaims(t, token)
		exp := int64(claims["exp"].(float64))
		iat := int64(claims["iat"].(float64))

		diff := exp - iat
		expectedDiff := int64((365 * 24 * time.Hour).Seconds())

		assert.InDelta(t, expectedDiff, diff, 2, "Token should be valid for ~1 year")
	})

	t.Run("WithJTI", func(t *testing.T) {
		jti := uuid.New().String()
		data := JWTData{
			ID:    "123",
			Role:  "admin",
			Email: testEmail,
			JTI:   jti,
		}

		token, err := createJWTToken(data, time.Hour)
		require.NoError(t, err)

		claims := testutils.ParseJWTClaims(t, token)
		assert.Equal(t, jti, claims["jti"], "JTI should be present in token")
	})

	t.Run("WithoutJTI", func(t *testing.T) {
		data := JWTData{
			ID:    "123",
			Role:  "admin",
			Email: testEmail,
		}

		token, err := createJWTToken(data, time.Hour)
		require.NoError(t, err)

		claims := testutils.ParseJWTClaims(t, token)
		assert.Nil(t, claims["jti"], "JTI should not be present when not provided")
	})
}

func TestAuthService_Login(t *testing.T) {
	testutils.SetupTestConfig(t)
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB
	mr := testutils.SetupTestRedis(t)
	defer mr.Close()

	t.Run("Success", func(t *testing.T) {
		email := "success@example.com"
		password := testPassword
		testutils.CreateTestUser(t, testDB, email, password)

		service := NewAuthService()
		result, err := service.Login(LoginDTO{
			Email:    email,
			Password: password,
		})

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, email, result.User.Email, "Returned user email should match")

		// Validate auth token
		authClaims := testutils.ParseJWTClaims(t, result.AuthToken)
		assert.Equal(t, result.User.ID, authClaims["sub"])
		assert.Equal(t, result.User.Email, authClaims["email"])
		assert.Equal(t, result.User.Role, authClaims["role"])
		assert.NotNil(t, authClaims["exp"])
		assert.Nil(t, authClaims["jti"], "Auth token should not have JTI")

		// Validate refresh token
		refreshClaims := testutils.ParseJWTClaims(t, result.RefreshToken)
		assert.Equal(t, result.User.ID, refreshClaims["sub"])
		assert.Equal(t, result.User.Email, refreshClaims["email"])
		assert.Equal(t, result.User.Role, refreshClaims["role"])
		assert.NotNil(t, refreshClaims["exp"])
		assert.NotEmpty(t, refreshClaims["jti"], "Refresh token must have JTI claim")
		assert.Equal(t, result.RefreshJTI, refreshClaims["jti"], "JTI should match")
	})

	t.Run("WrongPassword", func(t *testing.T) {
		email := "wrongpass@example.com"
		testutils.CreateTestUser(t, testDB, email, "correctpassword")

		service := NewAuthService()
		result, err := service.Login(LoginDTO{
			Email:    email,
			Password: "Wrongpassword123*",
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrInvalidCredentials, "Should return invalid credentials error")
	})

	t.Run("UserNotFound", func(t *testing.T) {
		service := NewAuthService()
		result, err := service.Login(LoginDTO{
			Email:    "nonexistent@example.com",
			Password: testPassword,
		})

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, ErrInvalidCredentials, "Should return invalid credentials error (anti-enumeration)")
	})

	t.Run("DBError", func(t *testing.T) {
		failingDB := testutils.SetupFailingDB(t)
		database.DB.DB = failingDB

		service := NewAuthService()
		_, err := service.Login(LoginDTO{
			Email:    testEmail,
			Password: testPassword,
		})

		assert.Error(t, err, "Expected DB error")
		assert.ErrorIs(t, err, ErrInvalidCredentials, "Should mask DB errors")

		// Restore DB
		database.DB.DB = testDB
	})

	t.Run("SQLInjection", func(t *testing.T) {
		testutils.CreateTestUser(t, testDB, "victim@example.com", "password123")
		service := NewAuthService()

		sqlInjectionAttempts := []string{
			"' OR '1'='1",
			"admin'--",
			"' OR '1'='1' --",
			"'; DROP TABLE users; --",
			"' UNION SELECT * FROM users --",
		}

		for _, injection := range sqlInjectionAttempts {
			t.Run("Injection_"+injection, func(t *testing.T) {
				_, err := service.Login(LoginDTO{
					Email:    injection,
					Password: "password",
				})

				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidEmailFormat, "SQL injection should be blocked by email validation")
			})
		}
	})

	t.Run("RefreshTokenExpiry", func(t *testing.T) {
		email := "refreshexpiry@example.com"
		password := testPassword
		testutils.CreateTestUser(t, testDB, email, password)

		service := NewAuthService()
		result, err := service.Login(LoginDTO{Email: email, Password: password})
		require.NoError(t, err)

		authClaims := testutils.ParseJWTClaims(t, result.AuthToken)
		refreshClaims := testutils.ParseJWTClaims(t, result.RefreshToken)

		authExp := int64(authClaims["exp"].(float64))
		refreshExp := int64(refreshClaims["exp"].(float64))

		assert.Greater(t, refreshExp, authExp, "Refresh token should have longer expiry than auth token")
		assert.NotEmpty(t, refreshClaims["jti"], "Refresh token must have JTI claim")
		assert.Equal(t, result.RefreshJTI, refreshClaims["jti"], "JTI should match")
		assert.Nil(t, authClaims["jti"], "Auth token should not have JTI")
	})
}

func TestAuthService_Login_WithRateLimiting(t *testing.T) {
	testutils.SetupTestConfig(t)

	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB

	mr := testutils.SetupTestRedis(t)
	defer mr.Close()

	t.Run("BlockAfter5FailedAttempts", func(t *testing.T) {
		email := "ratelimit@example.com"
		password := "TestPassword123!"
		testutils.CreateTestUser(t, testDB, email, password)

		service := NewAuthService()

		for i := 0; i < 5; i++ {
			_, err := service.Login(LoginDTO{
				Email:    email,
				Password: password + "wrong",
			})
			assert.ErrorIs(t, err, ErrInvalidCredentials, "Attempt %d should fail", i+1)
		}

		_, err := service.Login(LoginDTO{
			Email:    email,
			Password: password,
		})
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAccountLocked, "Account should be locked after 5 failed attempts")
	})

	t.Run("ResetAfterSuccessfulLogin", func(t *testing.T) {
		email := "resetaftersuccess@example.com"
		password := "TestPassword123!"
		testutils.CreateTestUser(t, testDB, email, password)

		service := NewAuthService()

		for i := 0; i < 4; i++ {
			service.Login(LoginDTO{Email: email, Password: password + "wrong"})
		}

		result, err := service.Login(LoginDTO{Email: email, Password: password})
		require.NoError(t, err)
		assert.NotNil(t, result)

		for i := 0; i < 5; i++ {
			service.Login(LoginDTO{Email: email, Password: password + "wrong"})
		}

		_, err = service.Login(LoginDTO{Email: email, Password: password})
		assert.ErrorIs(t, err, ErrAccountLocked)
	})

	t.Run("LockoutExpiry", func(t *testing.T) {
		email := "lockoutexpiry@example.com"
		password := "TestPassword123!"
		testutils.CreateTestUser(t, testDB, email, password)

		service := NewAuthService()
		service.RateLimiter = &RateLimiter{
			maxAttempts:     3,
			window:          1 * time.Minute,
			lockoutDuration: 200 * time.Millisecond,
		}

		for i := 0; i < 3; i++ {
			service.Login(LoginDTO{Email: email, Password: password + "wrong"})
		}

		_, err := service.Login(LoginDTO{Email: email, Password: password})
		assert.ErrorIs(t, err, ErrAccountLocked)

		time.Sleep(250 * time.Millisecond)
		testutils.ClearRateLimitKeys(email)

		result, err := service.Login(LoginDTO{Email: email, Password: password})
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}
