package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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
		if err != nil {
			t.Fatal("Failed to perform login request\n", err.Error())
		}

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

func TestAuthController_GoogleLogin(t *testing.T) {
	app, _ := setupTestApp(t)

	t.Run("Redirects to Google OAuth URL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusFound, resp.StatusCode)

		// Check redirect location
		location := resp.Header.Get("Location")
		assert.NotEmpty(t, location)
		assert.Contains(t, location, "accounts.google.com/o/oauth2")
		assert.Contains(t, location, "client_id=")
		assert.Contains(t, location, "redirect_uri=")
		assert.Contains(t, location, "scope=")
		assert.Contains(t, location, "state=")
	})

	t.Run("Contains correct OAuth scopes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)

		location := resp.Header.Get("Location")
		assert.Contains(t, location, "userinfo.email")
		assert.Contains(t, location, "userinfo.profile")
	})

	t.Run("Uses correct client ID from env", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)

		location := resp.Header.Get("Location")
		clientID := os.Getenv("GOOGLE_CLIENT_ID")
		if clientID != "" {
			assert.Contains(t, location, "client_id="+clientID)
		}
	})

	t.Run("Includes state parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)

		location := resp.Header.Get("Location")
		state := os.Getenv("GOOGLE_STATE")
		if state != "" {
			assert.Contains(t, location, "state="+state)
		}
	})

	t.Run("Uses correct redirect URI", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)

		location := resp.Header.Get("Location")
		parsed, err := url.Parse(location)
		if err != nil {
			panic(err)
		}
		redirect := parsed.Query().Get("redirect_uri")

		assert.Contains(t, redirect, "http")
		assert.Contains(t, redirect, "/api/auth/google/callback")
	})
}

func TestAuthController_GoogleCallback(t *testing.T) {
	app, _ := setupTestApp(t)

	t.Run("Returns error on invalid state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=invalid_state&code=test_code", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		body := make([]byte, resp.ContentLength)
		_, err = resp.Body.Read(body)
		if err != nil && err.Error() != "EOF" {
			t.Logf("Warning: Failed to read response body: %v", err)
		}
		assert.Contains(t, string(body), "Invalid OAuth state")
	})

	t.Run("Returns error on missing state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?code=test_code", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Returns error on missing code", func(t *testing.T) {
		state := os.Getenv("GOOGLE_STATE")
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+state, nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response, "error")
	})

	t.Run("Returns error on invalid code", func(t *testing.T) {
		state := os.Getenv("GOOGLE_STATE")
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+state+"&code=invalid_code_12345", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response, "error")
		assert.Contains(t, response["error"], "failed to exchange token")
	})

	t.Run("Returns error with empty state and code", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Handles state with special characters", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=abc%20123&code=test", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Handles code with special characters", func(t *testing.T) {
		state := os.Getenv("GOOGLE_STATE")
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+state+"&code=test%2Bcode%3D123", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	// Note: Testing successful OAuth flow requires mocking Google's OAuth endpoints
	// These tests would need HTTP client mocking
	t.Run("Successfully exchanges code for user - requires mocking", func(t *testing.T) {
		t.Skip("Requires mocking Google OAuth endpoints")
	})

	t.Run("Creates new user on first Google login - requires mocking", func(t *testing.T) {
		t.Skip("Requires mocking Google OAuth endpoints")
	})

	t.Run("Returns existing user on subsequent login - requires mocking", func(t *testing.T) {
		t.Skip("Requires mocking Google OAuth endpoints")
	})

	t.Run("Handles Google API errors - requires mocking", func(t *testing.T) {
		t.Skip("Requires mocking Google OAuth endpoints")
	})

	t.Run("Handles malformed Google user info - requires mocking", func(t *testing.T) {
		t.Skip("Requires mocking Google OAuth endpoints")
	})
}

func TestGetGoogleOAuthConfig(t *testing.T) {
	t.Run("Returns valid OAuth config", func(t *testing.T) {
		config := GetGoogleOAuthConfig()

		assert.NotNil(t, config)
		assert.NotEmpty(t, config.RedirectURL)
		assert.Contains(t, config.RedirectURL, "/api/auth/google/callback")
		assert.NotEmpty(t, config.Scopes)
		assert.Contains(t, config.Scopes, "https://www.googleapis.com/auth/userinfo.email")
		assert.Contains(t, config.Scopes, "https://www.googleapis.com/auth/userinfo.profile")
		assert.NotNil(t, config.Endpoint)
	})

	t.Run("Uses environment variables", func(t *testing.T) {
		config := GetGoogleOAuthConfig()

		clientID := os.Getenv("GOOGLE_CLIENT_ID")
		clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

		assert.Equal(t, clientID, config.ClientID)
		assert.Equal(t, clientSecret, config.ClientSecret)
	})

	t.Run("Has correct redirect URL format", func(t *testing.T) {
		config := GetGoogleOAuthConfig()

		assert.Regexp(t, `^https?://.*`, config.RedirectURL)
		assert.Contains(t, config.RedirectURL, "localhost:8080")
	})

	t.Run("Uses Google OAuth endpoint", func(t *testing.T) {
		config := GetGoogleOAuthConfig()

		assert.Equal(t, "https://oauth2.googleapis.com/token", config.Endpoint.TokenURL)
		assert.Equal(t, "https://accounts.google.com/o/oauth2/auth", config.Endpoint.AuthURL)
	})
}
