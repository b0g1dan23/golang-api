package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"boge.dev/golang-api/api/user"
	database "boge.dev/golang-api/db"
	"boge.dev/golang-api/utils/testutils"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

const (
	validTestUserEmail    = "test@example.com"
	validTestUserPassword = "Password123*"
)

func setupTestApp(t *testing.T) (*fiber.App, *user.User) {
	t.Helper()

	// Setup test configuration
	testutils.SetupTestConfig(t)

	// Setup test database
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB

	// Setup miniRedis
	mr := testutils.SetupTestRedis(t)

	// Setup Fiber app
	app := fiber.New()
	RegisterAuthRoutes(app)

	// Create test user
	testUser := testutils.CreateTestUser(t, testDB, validTestUserEmail, validTestUserPassword)

	// Cleanup
	t.Cleanup(func() {
		testutils.CleanupTestDB(t, testDB)
		sqlDB, err := testDB.DB()
		if err != nil {
			t.Fatalf("Warning: Failed to get DB: %v", err)
		}
		err = sqlDB.Close()
		if err != nil {
			t.Logf("Warning: Failed to close test database: %v", err)
		}
		mr.Close()
	})

	return app, testUser
}

func TestAuthController_Login(t *testing.T) {
	app, _ := setupTestApp(t)

	t.Run("Success", func(t *testing.T) {
		loginData := LoginDTO{
			Email:    validTestUserEmail,
			Password: validTestUserPassword,
		}
		body, err := json.Marshal(loginData)
		if err != nil {
			t.Fatal("Failed to marshal login data\n", err.Error())
		}

		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Check cookies
		cookies := resp.Cookies()
		assert.NotEmpty(t, cookies)

		var authCookie, refreshCookie *http.Cookie
		for _, cookie := range cookies {
			if cookie.Name == "__Secure-auth_token" {
				authCookie = cookie
			}
			if cookie.Name == "__Host-refresh_token" {
				refreshCookie = cookie
			}
		}

		assert.NotNil(t, authCookie)
		assert.NotNil(t, refreshCookie)
		assert.True(t, authCookie.HttpOnly)
		assert.True(t, refreshCookie.HttpOnly)
	})

	t.Run("Invalid Credentials", func(t *testing.T) {
		loginData := LoginDTO{
			Email:    validTestUserEmail,
			Password: "Password321*",
		}
		body, err := json.Marshal(loginData)
		if err != nil {
			t.Fatal("Failed to marshal login data\n", err.Error())
		}

		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("User not found", func(t *testing.T) {
		loginData := LoginDTO{
			Email:    "nonexistent@example.com",
			Password: "Password123*",
		}
		body, err := json.Marshal(loginData)
		if err != nil {
			t.Fatal("Failed to marshal login data\n", err.Error())
		}

		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Invalid request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Missing email", func(t *testing.T) {
		loginData := LoginDTO{
			Password: "Password1234/",
		}
		body, err := json.Marshal(loginData)
		if err != nil {
			t.Fatal("Failed to marshal login data\n", err.Error())
		}

		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}

func TestAuthController_Logout(t *testing.T) {
	app, _ := setupTestApp(t)

	t.Run("Success", func(t *testing.T) {
		loginData := LoginDTO{
			Email:    validTestUserEmail,
			Password: validTestUserPassword,
		}
		body, err := json.Marshal(loginData)
		if err != nil {
			t.Fatal("Failed to marshal login data\n", err.Error())
		}

		loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		loginReq.Header.Set("Content-Type", "application/json")
		loginResp, err := app.Test(loginReq)
		if err != nil {
			t.Fatal("Failed to perform login request\n", err.Error())
		}

		// Extract refresh token from login response
		var refreshToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Host-refresh_token" {
				refreshToken = cookie.Value
				break
			}
		}

		// Test logout
		logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		logoutReq.AddCookie(&http.Cookie{
			Name:  "__Host-refresh_token",
			Value: refreshToken,
		})

		logoutResp, err := app.Test(logoutReq)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, logoutResp.StatusCode)
	})

	t.Run("No cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestAuthController_RefreshToken(t *testing.T) {
	app, _ := setupTestApp(t)

	t.Run("Success", func(t *testing.T) {
		loginData := LoginDTO{
			Email:    validTestUserEmail,
			Password: validTestUserPassword,
		}
		body, err := json.Marshal(loginData)
		if err != nil {
			t.Fatal("Failed to marshal login data\n", err.Error())
		}

		loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(body))
		loginReq.Header.Set("Content-Type", "application/json")
		loginResp, err := app.Test(loginReq)

		// Extract refresh token
		var refreshToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Host-refresh_token" {
				refreshToken = cookie.Value
				break
			}
		}

		// Test refresh
		refreshReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
		refreshReq.AddCookie(&http.Cookie{
			Name:  "__Host-refresh_token",
			Value: refreshToken,
		})

		refreshResp, err := app.Test(refreshReq)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, refreshResp.StatusCode)

		// Check new tokens are returned
		newCookies := refreshResp.Cookies()
		assert.NotEmpty(t, newCookies)
	})

	t.Run("No token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-refresh_token",
			Value: "invalid.token.here",
		})

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
