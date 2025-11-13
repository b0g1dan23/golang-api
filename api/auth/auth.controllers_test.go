package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	database "boge.dev/golang-api/db"
	"boge.dev/golang-api/utils/testutils"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

const (
	validTestUserEmail    = "test@example.com"
	validTestUserPassword = "Password123*"
)

func setupTestApp(t *testing.T) *fiber.App {
	t.Helper()

	// Setup test configuration
	testutils.SetupTestConfig(t)

	// Setup test database
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB

	// Setup Fiber app
	app := fiber.New()
	RegisterAuthRoutes(app)

	mr := testutils.SetupTestRedis(t)

	// Create test user
	testutils.CreateTestUser(t, testDB, validTestUserEmail, validTestUserPassword)

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

	return app
}

func TestAuthController_Login(t *testing.T) {
	app := setupTestApp(t)

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

func TestAuthController_RegisterUser(t *testing.T) {
	app := setupTestApp(t)

	t.Run("Success", func(t *testing.T) {
		newUser := map[string]interface{}{
			"email":     "newuser@example.com",
			"password":  "SecurePass123!",
			"firstname": "John",
			"lastname":  "Doe",
		}
		body, err := json.Marshal(newUser)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		// Check response body
		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "newuser@example.com", response["email"])
		assert.Equal(t, "John", response["firstname"])
		assert.Equal(t, "Doe", response["lastname"])
		assert.NotContains(t, response, "password", "Password should not be returned")

		// Check cookies are set
		cookies := resp.Cookies()
		var hasAuthToken, hasRefreshToken bool
		for _, cookie := range cookies {
			if cookie.Name == "__Secure-auth_token" {
				hasAuthToken = true
			}
			if cookie.Name == "__Host-refresh_token" {
				hasRefreshToken = true
			}
		}
		assert.True(t, hasAuthToken, "Auth token cookie should be set")
		assert.True(t, hasRefreshToken, "Refresh token cookie should be set")
	})

	t.Run("Invalid request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "Invalid request body", response["error"])
	})

	t.Run("Duplicate email", func(t *testing.T) {
		duplicateUser := map[string]interface{}{
			"email":     validTestUserEmail, // Already exists from setupTestApp
			"password":  "AnotherPass123!",
			"firstname": "Jane",
			"lastname":  "Doe",
		}
		body, err := json.Marshal(duplicateUser)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "duplicate", "Should indicate duplicate email")
	})

	t.Run("Missing required fields", func(t *testing.T) {
		incompleteUser := map[string]interface{}{
			"email": "incomplete@example.com",
			// Missing password, firstname, lastname
		}
		body, err := json.Marshal(incompleteUser)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("Invalid email format", func(t *testing.T) {
		invalidEmailUser := map[string]interface{}{
			"email":     "not-an-email",
			"password":  "SecurePass123!",
			"firstname": "John",
			"lastname":  "Doe",
		}
		body, err := json.Marshal(invalidEmailUser)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		// Should either be 400 or 500 depending on validation
		assert.True(t, resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusInternalServerError)
	})
}

func TestAuthController_Logout(t *testing.T) {
	app := setupTestApp(t)

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

	t.Run("Success with request body (mobile)", func(t *testing.T) {
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

		// Test logout with body (mobile scenario)
		logoutBody := LogoutRequest{
			RefreshToken: refreshToken,
		}
		logoutBodyBytes, err := json.Marshal(logoutBody)
		assert.NoError(t, err)

		logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", bytes.NewReader(logoutBodyBytes))
		logoutReq.Header.Set("Content-Type", "application/json")

		logoutResp, err := app.Test(logoutReq)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, logoutResp.StatusCode)
	})

	t.Run("No cookie and no body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "No refresh token found", response["error"])
	})

	t.Run("Empty refresh token in body", func(t *testing.T) {
		logoutBody := LogoutRequest{
			RefreshToken: "",
		}
		body, err := json.Marshal(logoutBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "Refresh token not provided", response["error"])
	})

	t.Run("Invalid JSON body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "No refresh token found", response["error"])
	})

	t.Run("Invalid refresh token", func(t *testing.T) {
		logoutBody := LogoutRequest{
			RefreshToken: "invalid.token.here",
		}
		body, err := json.Marshal(logoutBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Clears cookies on successful logout", func(t *testing.T) {
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

		var refreshToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Host-refresh_token" {
				refreshToken = cookie.Value
				break
			}
		}

		logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		logoutReq.AddCookie(&http.Cookie{
			Name:  "__Host-refresh_token",
			Value: refreshToken,
		})

		logoutResp, err := app.Test(logoutReq)
		assert.NoError(t, err)

		// Check that cookies are cleared
		cookies := logoutResp.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "__Host-refresh_token" || cookie.Name == "__Secure-auth_token" {
				assert.Equal(t, "", cookie.Value)
				assert.Equal(t, 0, cookie.MaxAge)
			}
		}
	})
}

func TestAuthController_RefreshToken(t *testing.T) {
	app := setupTestApp(t)

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
	app := setupTestApp(t)
	google_client_id := os.Getenv("GOOGLE_CLIENT_ID")
	google_secret := os.Getenv("GOOGLE_CLIENT_SECRET")

	if google_client_id == "" || google_secret == "" {
		t.Skip("GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set; skipping Google OAuth tests")
	}

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

		parsedURL, err := url.Parse(location)
		assert.NoError(t, err)
		state := parsedURL.Query().Get("state")
		assert.NotEmpty(t, state, "State parameter should be present")

		exists, err := database.RDB.Client.Exists(req.Context(), fmt.Sprintf("oauth_state:%s", state)).Result()
		assert.NoError(t, err)
		assert.Equal(t, int64(1), exists, "State should be stored in Redis")
	})

	t.Run("Generates unique state for each request", func(t *testing.T) {
		req1 := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)
		resp1, err := app.Test(req1)
		assert.NoError(t, err)

		location1 := resp1.Header.Get("Location")
		parsedURL1, _ := url.Parse(location1)
		state1 := parsedURL1.Query().Get("state")

		req2 := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)
		resp2, err := app.Test(req2)
		assert.NoError(t, err)

		location2 := resp2.Header.Get("Location")
		parsedURL2, _ := url.Parse(location2)
		state2 := parsedURL2.Query().Get("state")

		assert.NotEqual(t, state1, state2, "Each request should generate a unique state")
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

	t.Run("Uses correct redirect URI", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)

		location := resp.Header.Get("Location")
		parsed, err := url.Parse(location)
		assert.NoError(t, err)
		redirect := parsed.Query().Get("redirect_uri")

		assert.Contains(t, redirect, "http")
		assert.Contains(t, redirect, "/api/auth/google/callback")
	})

	t.Run("State has minimum length for security", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)

		location := resp.Header.Get("Location")
		parsedURL, _ := url.Parse(location)
		state := parsedURL.Query().Get("state")

		// Base64 encoded 32 bytes should be at least 40 characters
		assert.GreaterOrEqual(t, len(state), 40, "State should be sufficiently long for security")
	})
}

func TestAuthController_GoogleCallback(t *testing.T) {
	app := setupTestApp(t)
	google_client_id := os.Getenv("GOOGLE_CLIENT_ID")
	google_secret := os.Getenv("GOOGLE_CLIENT_SECRET")

	if google_client_id == "" || google_secret == "" {
		t.Skip("GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not set; skipping Google OAuth tests")
	}

	getValidState := func(t *testing.T) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/login", nil)
		resp, err := app.Test(req)
		assert.NoError(t, err)

		location := resp.Header.Get("Location")
		parsedURL, err := url.Parse(location)
		assert.NoError(t, err)

		return parsedURL.Query().Get("state")
	}

	t.Run("Returns error on missing state parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?code=test_code", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "Missing OAuth state parameter")
	})

	t.Run("Returns error on invalid state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=invalid_random_state&code=test_code", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "Invalid or expired OAuth state")
	})

	t.Run("Returns error on missing code", func(t *testing.T) {
		state := getValidState(t)
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+state, nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "Missing authorization code")
	})

	t.Run("Deletes state after use (prevents replay)", func(t *testing.T) {
		state := getValidState(t)

		// First use - should work (but fail at code exchange)
		req1 := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+state+"&code=test_code", nil)
		resp1, err := app.Test(req1)
		assert.NoError(t, err)
		// Will fail at code exchange, but state should be deleted
		assert.Equal(t, http.StatusInternalServerError, resp1.StatusCode)

		// Second use - should fail because state was deleted
		req2 := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+state+"&code=test_code", nil)
		resp2, err := app.Test(req2)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp2.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "Invalid or expired OAuth state")
	})

	t.Run("Returns error with empty state and code", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Handles state with special characters", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=abc%20123&code=test", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Returns error on invalid authorization code", func(t *testing.T) {
		state := getValidState(t)
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state="+state+"&code=invalid_code_12345", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response, "error")
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

		appURL := os.Getenv("APP_URL")
		if appURL != "" {
			assert.Contains(t, config.RedirectURL, appURL)
		}
	})

	t.Run("Uses Google OAuth endpoint", func(t *testing.T) {
		config := GetGoogleOAuthConfig()

		assert.Equal(t, "https://oauth2.googleapis.com/token", config.Endpoint.TokenURL)
		assert.Equal(t, "https://accounts.google.com/o/oauth2/auth", config.Endpoint.AuthURL)
	})
}

func TestGenerateOAuthState(t *testing.T) {
	t.Run("Generates non-empty state", func(t *testing.T) {
		state, err := generateOAuthState()
		assert.NoError(t, err)
		assert.NotEmpty(t, state)
	})

	t.Run("Generates unique states", func(t *testing.T) {
		state1, err1 := generateOAuthState()
		state2, err2 := generateOAuthState()

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NotEqual(t, state1, state2)
	})

	t.Run("Generates base64 URL-safe string", func(t *testing.T) {
		state, err := generateOAuthState()
		assert.NoError(t, err)

		assert.NotContains(t, state, "+")
		assert.NotContains(t, state, "/")
	})

	t.Run("Generates sufficiently long state", func(t *testing.T) {
		state, err := generateOAuthState()
		assert.NoError(t, err)

		// 32 bytes base64 encoded should be at least 40 characters
		assert.GreaterOrEqual(t, len(state), 40)
	})
}
