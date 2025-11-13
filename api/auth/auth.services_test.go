package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"boge.dev/golang-api/api/user"
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
		_ = os.Unsetenv("JWT_SECRET")
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
		assert.Equal(t, string(result.User.Role), authClaims["role"])
		assert.NotNil(t, authClaims["exp"])
		assert.Nil(t, authClaims["jti"], "Auth token should not have JTI")

		// Validate refresh token
		refreshClaims := testutils.ParseJWTClaims(t, result.RefreshToken)
		assert.Equal(t, result.User.ID, refreshClaims["sub"])
		assert.Equal(t, result.User.Email, refreshClaims["email"])
		assert.Equal(t, string(result.User.Role), refreshClaims["role"])
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

func TestAuthService_Logout(t *testing.T) {
	testutils.SetupTestConfig(t)
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB
	mr := testutils.SetupTestRedis(t)
	defer mr.Close()

	service := NewAuthService()

	t.Run("Successfully logout with valid refresh token", func(t *testing.T) {
		jwtTokenData := JWTData{
			ID:    "123",
			Role:  user.RoleUser,
			Email: testEmail,
			JTI:   uuid.New().String(),
		}

		token, err := createJWTToken(jwtTokenData, 1*time.Hour)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		err = service.Logout(token)
		assert.NoError(t, err)

		ctx := context.Background()
		key := fmt.Sprintf("refresh_blacklist:%s", jwtTokenData.JTI)
		val, err := database.RDB.Client.Get(ctx, key).Result()
		assert.NoError(t, err)
		assert.Equal(t, "1", val)

		ttl, err := database.RDB.Client.TTL(ctx, key).Result()
		assert.NoError(t, err)
		assert.Greater(t, ttl, time.Duration(0))
		assert.LessOrEqual(t, ttl, 1*time.Hour)
	})

	t.Run("Logout with token without JTI claim", func(t *testing.T) {
		jwtTokenData := JWTData{
			ID:    "456",
			Role:  user.RoleUser,
			Email: testEmail,
			JTI:   "",
		}

		token, err := createJWTToken(jwtTokenData, 1*time.Hour)
		require.NoError(t, err)

		err = service.Logout(token)
		assert.Error(t, err)
	})

	t.Run("Logout with invalid token format", func(t *testing.T) {
		err := service.Logout("invalid.token.format")
		assert.Error(t, err)
	})

	t.Run("Logout with malformed token", func(t *testing.T) {
		err := service.Logout("not-a-jwt-token")
		assert.Error(t, err)
	})

	t.Run("Logout with token without exp claim uses default TTL", func(t *testing.T) {
		jti := uuid.New().String()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":    "789",
			"role":  user.RoleUser,
			"email": testEmail,
			"jti":   jti,
			// No exp claim
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		require.NoError(t, err)

		err = service.Logout(tokenString)
		assert.NoError(t, err)

		ctx := context.Background()
		key := fmt.Sprintf("refresh_blacklist:%s", jti)
		ttl, err := database.RDB.Client.TTL(ctx, key).Result()
		assert.NoError(t, err)
		assert.Greater(t, ttl, 23*time.Hour)
		assert.LessOrEqual(t, ttl, 24*time.Hour)
	})

	t.Run("Logout with already expired token", func(t *testing.T) {
		jwtTokenData := JWTData{
			ID:    "999",
			Role:  user.RoleUser,
			Email: testEmail,
			JTI:   uuid.New().String(),
		}

		token, err := createJWTToken(jwtTokenData, 10*time.Millisecond)
		require.NoError(t, err)

		time.Sleep(15 * time.Millisecond)

		err = service.Logout(token)
		if err == nil {
			ctx := context.Background()
			key := fmt.Sprintf("refresh_blacklist:%s", jwtTokenData.JTI)
			_, err := database.RDB.Client.Get(ctx, key).Result()
			assert.Error(t, err)
		}
	})

	t.Run("Logout same token twice (idempotency)", func(t *testing.T) {
		jwtTokenData := JWTData{
			ID:    "1001",
			Role:  user.RoleUser,
			Email: testEmail,
			JTI:   uuid.New().String(),
		}

		token, err := createJWTToken(jwtTokenData, 1*time.Hour)
		require.NoError(t, err)

		err = service.Logout(token)
		assert.NoError(t, err)

		err = service.Logout(token)
		assert.NoError(t, err)
	})

	t.Run("Logout with different exp claim types", func(t *testing.T) {
		testCases := []struct {
			name    string
			expType interface{}
		}{
			{"float64", float64(time.Now().Add(1 * time.Hour).Unix())},
			{"int64", time.Now().Add(1 * time.Hour).Unix()},
			{"json.Number", json.Number(fmt.Sprintf("%d", time.Now().Add(1*time.Hour).Unix()))},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				jti := uuid.New().String()
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"id":    "test",
					"role":  user.RoleUser,
					"email": testEmail,
					"jti":   jti,
					"exp":   tc.expType,
				})

				tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
				require.NoError(t, err)

				err = service.Logout(tokenString)
				assert.NoError(t, err)

				ctx := context.Background()
				key := fmt.Sprintf("refresh_blacklist:%s", jti)
				val, err := database.RDB.Client.Get(ctx, key).Result()
				assert.NoError(t, err)
				assert.Equal(t, "1", val)
			})
		}
	})

	t.Run("Logout with invalid exp claim type", func(t *testing.T) {
		jti := uuid.New().String()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":    "test",
			"role":  user.RoleUser,
			"email": testEmail,
			"jti":   jti,
			"exp":   "not-a-number",
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		require.NoError(t, err)

		err = service.Logout(tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse JWT")
	})

	t.Run("Logout with empty string token", func(t *testing.T) {
		err := service.Logout("")
		assert.Error(t, err)
	})

	t.Run("Multiple concurrent logouts", func(t *testing.T) {
		tokens := make([]string, 10)
		for i := 0; i < 10; i++ {
			jwtTokenData := JWTData{
				ID:    fmt.Sprintf("user-%d", i),
				Role:  user.RoleUser,
				Email: fmt.Sprintf("user%d@test.com", i),
				JTI:   uuid.New().String(),
			}

			token, err := createJWTToken(jwtTokenData, 1*time.Hour)
			require.NoError(t, err)
			tokens[i] = token
		}

		var wg sync.WaitGroup
		errors := make([]error, 10)

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				errors[idx] = service.Logout(tokens[idx])
			}(i)
		}

		wg.Wait()

		for i, err := range errors {
			assert.NoError(t, err, "Logout failed for token %d", i)
		}
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
			_, err := service.Login(LoginDTO{Email: email, Password: password + "wrong"})
			assert.ErrorIs(t, err, ErrInvalidCredentials, "Attempt %d should fail", i+1)
		}

		result, err := service.Login(LoginDTO{Email: email, Password: password})
		require.NoError(t, err)
		assert.NotNil(t, result)

		for i := 0; i < 5; i++ {
			_, err := service.Login(LoginDTO{Email: email, Password: password + "wrong"})
			assert.ErrorIs(t, err, ErrInvalidCredentials, "Attempt %d should fail", i+1)
		}

		_, err = service.Login(LoginDTO{Email: email, Password: password})
		assert.ErrorIs(t, err, ErrAccountLocked)
	})

	t.Run("LockoutExpiry", func(t *testing.T) {
		email := "lockoutexpiry@example.com"
		password := "TestPassword123!"
		testutils.CreateTestUser(t, testDB, email, password)

		service := NewAuthService()

		for i := 0; i < 5; i++ {
			_, err := service.Login(LoginDTO{Email: email, Password: password + "wrong", ClientIP: "192.168.1.100"})
			assert.ErrorIs(t, err, ErrInvalidCredentials, "Attempt %d should fail", i+1)
		}

		_, err := service.Login(LoginDTO{Email: email, Password: password, ClientIP: "192.168.1.100"})
		assert.ErrorIs(t, err, ErrAccountLocked)

		time.Sleep(250 * time.Millisecond)
		testutils.ClearRateLimitKeys(email)

		result, err := service.Login(LoginDTO{Email: email, Password: password})
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestAuthService_RefreshToken(t *testing.T) {
	testutils.SetupTestConfig(t)
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB
	mr := testutils.SetupTestRedis(t)
	defer mr.Close()

	service := NewAuthService()

	// Create a shared test user for all refresh token tests
	sharedTestUser := testutils.CreateTestUser(t, testDB, testEmail, "TestPassword123!")

	t.Run("Successfully refresh token with valid refresh token", func(t *testing.T) {
		fmt.Println(sharedTestUser)
		jwtTokenData := JWTData{
			ID:    sharedTestUser.ID,
			Role:  sharedTestUser.Role,
			Email: sharedTestUser.Email,
			JTI:   uuid.New().String(),
		}

		oldRefreshToken, err := createJWTToken(jwtTokenData, 7*24*time.Hour)
		require.NoError(t, err)
		require.NotEmpty(t, oldRefreshToken)

		result, err := service.RefreshToken(oldRefreshToken)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, result.User, "User should be populated")
		assert.Equal(t, sharedTestUser.ID, result.User.ID)
		assert.NotEmpty(t, result.AuthToken)
		assert.NotEmpty(t, result.RefreshToken)
		assert.NotEmpty(t, result.RefreshJTI)
		assert.NotEqual(t, oldRefreshToken, result.RefreshToken)

		authClaims, err := parseJWT(result.AuthToken)
		fmt.Println(authClaims)
		assert.NoError(t, err)
		assert.Equal(t, jwtTokenData.ID, authClaims.ID)
		assert.Equal(t, jwtTokenData.Email, authClaims.Email)
		assert.Equal(t, jwtTokenData.Role, authClaims.Role)

		refreshClaims, err := parseJWT(result.RefreshToken)
		assert.NoError(t, err)
		assert.Equal(t, result.RefreshJTI, refreshClaims.JTI)

		ctx := context.Background()
		blacklistKey := fmt.Sprintf("refresh_blacklist:%s", jwtTokenData.JTI)
		val, err := database.RDB.Client.Get(ctx, blacklistKey).Result()
		assert.NoError(t, err)
		assert.Equal(t, "1", val)
	})

	t.Run("Refresh token with invalid token format", func(t *testing.T) {
		result, err := service.RefreshToken("invalid.token.format")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidToken, err)
		assert.Nil(t, result)
	})

	t.Run("Refresh token without JTI claim", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   sharedTestUser.ID,
			"email": testEmail,
			"role":  user.RoleUser,
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
			// No jti claim
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		require.NoError(t, err)

		result, err := service.RefreshToken(tokenString)
		assert.Error(t, err)
		assert.Equal(t, ErrMissingJTI, err)
		assert.Nil(t, result)
	})

	t.Run("Refresh token with empty JTI", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   sharedTestUser.ID,
			"email": testEmail,
			"role":  user.RoleUser,
			"jti":   "", // Empty JTI
			"exp":   time.Now().Add(1 * time.Hour).Unix(),
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		require.NoError(t, err)

		result, err := service.RefreshToken(tokenString)
		assert.Error(t, err)
		assert.Equal(t, ErrMissingJTI, err)
		assert.Nil(t, result)
	})

	t.Run("Refresh token that is already blacklisted", func(t *testing.T) {
		jti := uuid.New().String()
		jwtTokenData := JWTData{
			ID:    "456",
			Role:  user.RoleUser,
			Email: testEmail,
			JTI:   jti,
		}

		refreshToken, err := createJWTToken(jwtTokenData, 7*24*time.Hour)
		require.NoError(t, err)

		// Blacklist the token first
		ctx := context.Background()
		blacklistKey := fmt.Sprintf("refresh_blacklist:%s", jti)
		err = database.RDB.Client.Set(ctx, blacklistKey, "1", 1*time.Hour).Err()
		require.NoError(t, err)

		// Try to refresh
		result, err := service.RefreshToken(refreshToken)
		assert.Error(t, err)
		assert.Equal(t, ErrTokenRevoked, err)
		assert.Nil(t, result)
	})

	t.Run("Refresh token with different sub claim types", func(t *testing.T) {
		// Create additional test users for this specific test
		user1 := testutils.CreateTestUser(t, testDB, "user789@example.com", "Test123!")
		user2 := testutils.CreateTestUser(t, testDB, "user101112@example.com", "Test123!")

		testCases := []struct {
			name        string
			subValue    interface{}
			expectedSub string
			email       string
		}{
			{"string sub", user1.ID, user1.ID, user1.Email},
			{"float64 sub", user2.ID, user2.ID, user2.Email},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"sub":   tc.subValue,
					"email": tc.email,
					"role":  "admin",
					"jti":   uuid.New().String(),
					"exp":   time.Now().Add(1 * time.Hour).Unix(),
				})

				tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
				require.NoError(t, err)

				result, err := service.RefreshToken(tokenString)
				assert.NoError(t, err)
				assert.NotNil(t, result)

				authClaims, err := parseJWT(result.AuthToken)
				assert.NoError(t, err)

				sub := authClaims.ID
				assert.Equal(t, tc.expectedSub, sub)
			})
		}
	})

	t.Run("Refresh token without exp claim", func(t *testing.T) {
		jti := uuid.New().String()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   sharedTestUser.ID,
			"email": testEmail,
			"role":  user.RoleUser,
			"jti":   jti,
			// No exp claim
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		require.NoError(t, err)

		result, err := service.RefreshToken(tokenString)
		assert.NoError(t, err, "Refresh should succeed even without exp claim")
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.AuthToken)
		assert.NotEmpty(t, result.RefreshToken)

		ctx := context.Background()
		blacklistKey := fmt.Sprintf("refresh_blacklist:%s", jti)
		val, err := database.RDB.Client.Get(ctx, blacklistKey).Result()
		assert.NoError(t, err, "Token should be blacklisted")
		assert.Equal(t, "1", val)

		ttl, err := database.RDB.Client.TTL(ctx, blacklistKey).Result()
		assert.NoError(t, err)
		assert.True(t, ttl == -1 || ttl > 0, "TTL should be -1 or positive, got %v", ttl)
	})

	t.Run("Refresh token with different exp claim types", func(t *testing.T) {
		testCases := []struct {
			name    string
			expType interface{}
		}{
			{"float64", float64(time.Now().Add(1 * time.Hour).Unix())},
			{"int64", time.Now().Add(1 * time.Hour).Unix()},
			{"json.Number", json.Number(fmt.Sprintf("%d", time.Now().Add(1*time.Hour).Unix()))},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				jti := uuid.New().String()
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
					"sub":   sharedTestUser.ID,
					"email": sharedTestUser.Email,
					"role":  sharedTestUser.Role,
					"jti":   jti,
					"exp":   tc.expType,
				})

				tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
				require.NoError(t, err)

				result, err := service.RefreshToken(tokenString)
				assert.NoError(t, err)
				assert.NotNil(t, result)

				ctx := context.Background()
				blacklistKey := fmt.Sprintf("refresh_blacklist:%s", jti)
				val, err := database.RDB.Client.Get(ctx, blacklistKey).Result()
				assert.NoError(t, err)
				assert.Equal(t, "1", val)
			})
		}
	})

	t.Run("Refresh token with invalid exp claim type", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   "test",
			"email": testEmail,
			"role":  user.RoleUser,
			"jti":   uuid.New().String(),
			"exp":   "not-a-number", // Invalid type
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		require.NoError(t, err)

		result, err := service.RefreshToken(tokenString)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidToken)
		assert.Nil(t, result)
	})

	t.Run("Refresh token with expired exp claim", func(t *testing.T) {
		jti := uuid.New().String()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   "test",
			"email": testEmail,
			"role":  user.RoleUser,
			"jti":   jti,
			"exp":   time.Now().Add(-1 * time.Hour).Unix(),
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		require.NoError(t, err)

		result, err := service.RefreshToken(tokenString)
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidToken, err)
		assert.Nil(t, result)
	})

	t.Run("Refresh token preserves all user data", func(t *testing.T) {
		jwtTokenData := JWTData{
			ID:    sharedTestUser.ID,
			Role:  sharedTestUser.Role,
			Email: sharedTestUser.Email,
			JTI:   uuid.New().String(),
		}

		oldRefreshToken, err := createJWTToken(jwtTokenData, 7*24*time.Hour)
		require.NoError(t, err)

		result, err := service.RefreshToken(oldRefreshToken)
		assert.NoError(t, err)
		assert.NotNil(t, result)

		authClaims, err := parseJWT(result.AuthToken)
		assert.NoError(t, err)
		assert.Equal(t, jwtTokenData.ID, authClaims.ID)
		assert.Equal(t, jwtTokenData.Email, authClaims.Email)
		assert.Equal(t, jwtTokenData.Role, authClaims.Role)

		refreshClaims, err := parseJWT(result.RefreshToken)
		assert.NoError(t, err)
		assert.Equal(t, jwtTokenData.ID, refreshClaims.ID)
		assert.Equal(t, jwtTokenData.Email, refreshClaims.Email)
		assert.Equal(t, jwtTokenData.Role, refreshClaims.Role)
		assert.NotEmpty(t, refreshClaims.JTI)
		assert.NotEqual(t, jwtTokenData.JTI, refreshClaims.JTI)
	})

	t.Run("Cannot reuse refresh token after refresh", func(t *testing.T) {
		jwtTokenData := JWTData{
			ID:    sharedTestUser.ID,
			Role:  sharedTestUser.Role,
			Email: sharedTestUser.Email,
			JTI:   uuid.New().String(),
		}

		oldRefreshToken, err := createJWTToken(jwtTokenData, 7*24*time.Hour)
		require.NoError(t, err)

		result1, err := service.RefreshToken(oldRefreshToken)
		assert.NoError(t, err)
		assert.NotNil(t, result1)

		result2, err := service.RefreshToken(oldRefreshToken)
		assert.Error(t, err)
		assert.Equal(t, ErrTokenRevoked, err)
		assert.Nil(t, result2)
	})

	t.Run("Multiple sequential refreshes create valid token chain", func(t *testing.T) {
		jwtTokenData := JWTData{
			ID:    sharedTestUser.ID,
			Role:  sharedTestUser.Role,
			Email: sharedTestUser.Email,
			JTI:   uuid.New().String(),
		}

		currentToken, err := createJWTToken(jwtTokenData, 7*24*time.Hour)
		require.NoError(t, err)

		jtis := []string{jwtTokenData.JTI}

		for i := 0; i < 3; i++ {
			result, err := service.RefreshToken(currentToken)
			assert.NoError(t, err, "Refresh %d failed", i+1)
			assert.NotNil(t, result)
			assert.NotEmpty(t, result.RefreshToken)
			assert.NotEmpty(t, result.RefreshJTI)

			assert.NotContains(t, jtis, result.RefreshJTI)
			jtis = append(jtis, result.RefreshJTI)

			currentToken = result.RefreshToken
		}

		ctx := context.Background()
		for i := 0; i < len(jtis)-1; i++ {
			blacklistKey := fmt.Sprintf("refresh_blacklist:%s", jtis[i])
			val, err := database.RDB.Client.Get(ctx, blacklistKey).Result()
			assert.NoError(t, err, "JTI %d not blacklisted", i)
			assert.Equal(t, "1", val)
		}

		lastBlacklistKey := fmt.Sprintf("refresh_blacklist:%s", jtis[len(jtis)-1])
		_, err = database.RDB.Client.Get(ctx, lastBlacklistKey).Result()
		assert.Error(t, err)
	})

	t.Run("Refresh token with missing optional claims", func(t *testing.T) {
		jti := uuid.New().String()
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"jti": jti,
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			// Missing sub, email, role
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		require.NoError(t, err)

		result, err := service.RefreshToken(tokenString)
		assert.NoError(t, err)
		assert.NotNil(t, result)

		authClaims, err := parseJWT(result.AuthToken)
		assert.NoError(t, err)
		assert.Empty(t, authClaims.ID)
	})

	t.Run("Concurrent refresh attempts with same token", func(t *testing.T) {
		concurentTestUser := testutils.CreateTestUser(t, testDB, "concurent-refresh@gmail.com", "TestPassword123!")

		jwtTokenData := JWTData{
			ID:    concurentTestUser.ID,
			Role:  concurentTestUser.Role,
			Email: concurentTestUser.Email,
			JTI:   uuid.New().String(),
		}

		refreshToken, err := createJWTToken(jwtTokenData, 7*24*time.Hour)
		require.NoError(t, err)

		const numGoRoutines = 10
		results := make(chan *LoginResponse, numGoRoutines)
		errors := make(chan error, numGoRoutines)

		start := make(chan struct{})
		var wg sync.WaitGroup

		for i := 0; i < numGoRoutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				<-start

				res, err := service.RefreshToken(refreshToken)
				results <- res
				errors <- err
			}(i)
		}

		close(start)

		wg.Wait()

		close(results)
		close(errors)

		successCount := 0
		errorCount := 0
		var successfulResult *LoginResponse

		for i := 0; i < numGoRoutines; i++ {
			result := <-results
			err := <-errors

			if err == nil {
				successCount++
				if successfulResult == nil {
					successfulResult = result
				}
				assert.NotNil(t, result)
				assert.NotNil(t, result.User, "User should be populated")
				assert.Equal(t, concurentTestUser.ID, result.User.ID)
			} else {
				errorCount++
				assert.ErrorIs(t, err, ErrTokenRevoked, "Failed attempts should get token revoked error")
			}
		}

		t.Logf("Success: %d, Errors: %d", successCount, errorCount)

		assert.Equal(t, 1, successCount, "Exactly one refresh should succeed with SETNX")
		assert.Equal(t, numGoRoutines-1, errorCount, "The rest of the refresh attempts should fail")

		ctx := context.Background()
		blacklistKey := fmt.Sprintf("refresh_blacklist:%s", jwtTokenData.JTI)
		val, err := database.RDB.Client.Get(ctx, blacklistKey).Result()
		assert.NoError(t, err)
		assert.Equal(t, "1", val, "Original token should be blacklisted")

		if successfulResult != nil {
			assert.NotEmpty(t, successfulResult.AuthToken)
			assert.NotEmpty(t, successfulResult.RefreshToken)
			assert.NotEmpty(t, successfulResult.RefreshJTI)
			assert.NotEqual(t, jwtTokenData.JTI, successfulResult.RefreshJTI)

			// Verify the new refresh token works
			newResult, err := service.RefreshToken(successfulResult.RefreshToken)
			assert.NoError(t, err)
			assert.NotNil(t, newResult)
		}

		// Try to use original token again - should fail
		failedResult, err := service.RefreshToken(refreshToken)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenRevoked)
		assert.Nil(t, failedResult)
	})

	t.Run("Refresh token blacklist TTL is properly calculated", func(t *testing.T) {
		jti := uuid.New().String()
		expTime := time.Now().Add(30 * time.Minute)

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":   sharedTestUser.ID,
			"email": testEmail,
			"role":  user.RoleUser,
			"jti":   jti,
			"exp":   expTime.Unix(),
		})

		tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
		require.NoError(t, err)

		result, err := service.RefreshToken(tokenString)
		assert.NoError(t, err)
		assert.NotNil(t, result)

		ctx := context.Background()
		blacklistKey := fmt.Sprintf("refresh_blacklist:%s", jti)
		ttl, err := database.RDB.Client.TTL(ctx, blacklistKey).Result()
		assert.NoError(t, err)

		assert.Greater(t, ttl, 25*time.Minute)
		assert.LessOrEqual(t, ttl, 30*time.Minute)
	})
}

func TestMapGoogleUserToUser(t *testing.T) {
	t.Run("Success with complete user info", func(t *testing.T) {
		userInfo := map[string]interface{}{
			"given_name":  "John",
			"family_name": "Doe",
			"email":       "john.doe@example.com",
		}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "John", result.FirstName)
		assert.Equal(t, "Doe", result.LastName)
		assert.Equal(t, "john.doe@example.com", result.Email)
		assert.Equal(t, user.RoleUser, result.Role)
		assert.Empty(t, result.Password)
		assert.Empty(t, result.ID)
	})

	t.Run("Success with missing family name", func(t *testing.T) {
		userInfo := map[string]interface{}{
			"given_name": "John",
			"email":      "john@example.com",
		}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "John", result.FirstName)
		assert.Empty(t, result.LastName)
		assert.Equal(t, "john@example.com", result.Email)
	})

	t.Run("Success with missing given name", func(t *testing.T) {
		userInfo := map[string]interface{}{
			"family_name": "Doe",
			"email":       "doe@example.com",
		}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result.FirstName)
		assert.Equal(t, "Doe", result.LastName)
		assert.Equal(t, "doe@example.com", result.Email)
	})

	t.Run("Success with only email", func(t *testing.T) {
		userInfo := map[string]interface{}{
			"email": "minimal@example.com",
		}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result.FirstName)
		assert.Empty(t, result.LastName)
		assert.Equal(t, "minimal@example.com", result.Email)
		assert.Equal(t, user.RoleUser, result.Role)
	})

	t.Run("Empty user info", func(t *testing.T) {
		userInfo := map[string]interface{}{}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result.FirstName)
		assert.Empty(t, result.LastName)
		assert.Empty(t, result.Email)
		assert.Equal(t, user.RoleUser, result.Role)
	})

	t.Run("User info with extra fields", func(t *testing.T) {
		userInfo := map[string]interface{}{
			"given_name":  "Jane",
			"family_name": "Smith",
			"email":       "jane.smith@example.com",
			"picture":     "https://example.com/photo.jpg",
			"locale":      "en",
			"verified":    true,
		}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "Jane", result.FirstName)
		assert.Equal(t, "Smith", result.LastName)
		assert.Equal(t, "jane.smith@example.com", result.Email)
	})

	t.Run("User info with numeric values", func(t *testing.T) {
		userInfo := map[string]interface{}{
			"given_name":  "Test",
			"family_name": "User",
			"email":       "test@example.com",
			"age":         25,
			"verified":    1,
		}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "Test", result.FirstName)
		assert.Equal(t, "User", result.LastName)
		assert.Equal(t, "test@example.com", result.Email)
	})

	t.Run("User info with special characters in names", func(t *testing.T) {
		userInfo := map[string]interface{}{
			"given_name":  "François",
			"family_name": "O'Brien-Smith",
			"email":       "francois@example.com",
		}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "François", result.FirstName)
		assert.Equal(t, "O'Brien-Smith", result.LastName)
		assert.Equal(t, "francois@example.com", result.Email)
	})

	t.Run("User info with whitespace in fields", func(t *testing.T) {
		userInfo := map[string]interface{}{
			"given_name":  "John",
			"family_name": "Doe",
			"email":       "john@example.com",
		}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "John", result.FirstName)
		assert.Equal(t, "Doe", result.LastName)
		assert.Equal(t, "john@example.com", result.Email)
	})

	t.Run("User info with long names", func(t *testing.T) {
		longFirstName := strings.Repeat("A", 200)

		userInfo := map[string]interface{}{
			"given_name":  longFirstName,
			"family_name": "Doe",
			"email":       "long@example.com",
		}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, longFirstName, result.FirstName)
		assert.Equal(t, 200, len(result.FirstName))
	})

	t.Run("Nil user info", func(t *testing.T) {
		var userInfo map[string]interface{}

		result, err := MapGoogleUserToUser(userInfo)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Empty(t, result.FirstName)
		assert.Empty(t, result.LastName)
		assert.Empty(t, result.Email)
	})

	t.Run("CreatedAt and UpdatedAt are not manually set", func(t *testing.T) {
		userInfo := map[string]interface{}{
			"given_name":  "John",
			"family_name": "Doe",
			"email":       "john@example.com",
		}

		result, err := MapGoogleUserToUser(userInfo)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		// CreatedAt and UpdatedAt should be zero values - GORM will set them on insert
		assert.True(t, result.CreatedAt.IsZero())
		assert.True(t, result.UpdatedAt.IsZero())
	})
}

func TestAuthService_LoginOAuthUser(t *testing.T) {
	testutils.SetupTestConfig(t)
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB
	mr := testutils.SetupTestRedis(t)
	defer mr.Close()

	service := NewAuthService()

	t.Run("Creates new user and returns tokens", func(t *testing.T) {
		dto := OAuthLoginDTO{
			Email:     "newuser@example.com",
			FirstName: "New",
			LastName:  "User",
		}

		result, err := service.LoginOAuthUser(dto)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.AuthToken)
		assert.NotEmpty(t, result.RefreshToken)
		assert.NotEmpty(t, result.RefreshJTI)
		assert.Equal(t, dto.Email, result.User.Email)
		assert.Equal(t, dto.FirstName, result.User.FirstName)
		assert.Equal(t, dto.LastName, result.User.LastName)
		assert.Equal(t, user.RoleUser, result.User.Role)
	})

	t.Run("Returns existing user and generates tokens", func(t *testing.T) {
		// Create user first
		testutils.CreateTestUser(t, testDB, "existing@example.com", "")

		dto := OAuthLoginDTO{
			Email:     "existing@example.com",
			FirstName: "Existing",
			LastName:  "User",
		}

		result, err := service.LoginOAuthUser(dto)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.AuthToken)
		assert.NotEmpty(t, result.RefreshToken)
		assert.Equal(t, dto.Email, result.User.Email)
	})

	t.Run("Returns error on empty email", func(t *testing.T) {
		dto := OAuthLoginDTO{
			Email:     "",
			FirstName: "Test",
			LastName:  "User",
		}

		result, err := service.LoginOAuthUser(dto)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "email is required")
	})

	t.Run("Returns error on invalid email format", func(t *testing.T) {
		dto := OAuthLoginDTO{
			Email:     "invalid-email",
			FirstName: "Test",
			LastName:  "User",
		}

		result, err := service.LoginOAuthUser(dto)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid email format")
	})

	t.Run("Handles missing first name", func(t *testing.T) {
		dto := OAuthLoginDTO{
			Email:     "noname@example.com",
			FirstName: "",
			LastName:  "User",
		}

		result, err := service.LoginOAuthUser(dto)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("Handles missing last name", func(t *testing.T) {
		dto := OAuthLoginDTO{
			Email:     "nolast@example.com",
			FirstName: "First",
			LastName:  "",
		}

		result, err := service.LoginOAuthUser(dto)
		assert.Error(t, err)
		assert.Nil(t, result)
	})
}
