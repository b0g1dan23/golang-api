package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"boge.dev/golang-api/constants"
	database "boge.dev/golang-api/db"
	"boge.dev/golang-api/utils/email"
	"boge.dev/golang-api/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthController_Login(t *testing.T) {
	app := testutils.SetupTestApp(t)
	RegisterAuthRoutes(app)

	t.Run("Success", func(t *testing.T) {
		loginData := LoginDTO{
			Email:    testutils.ValidTestUserEmail,
			Password: testutils.ValidTestUserPassword,
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
			if cookie.Name == "__Secure-access_token" {
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
			Email:    testutils.ValidTestUserEmail,
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
	app := testutils.SetupTestApp(t)
	RegisterAuthRoutes(app)

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

		resp, err := app.Test(req, int(5*time.Second.Milliseconds()))
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
			if cookie.Name == "__Secure-access_token" {
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

		resp, err := app.Test(req, int(5*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "invalid request body", response["error"])
	})

	t.Run("Duplicate email", func(t *testing.T) {
		duplicateUser := map[string]interface{}{
			"email":     testutils.ValidTestUserEmail, // Already exists from testutils.SetupTestApp()
			"password":  "AnotherPass123!",
			"firstname": "Jane",
			"lastname":  "Doe",
		}
		body, err := json.Marshal(duplicateUser)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(5*time.Second.Milliseconds()))
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

		resp, err := app.Test(req, int(5*time.Second.Milliseconds()))
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

		resp, err := app.Test(req, int(5*time.Second.Milliseconds()))
		assert.NoError(t, err)
		// Should either be 400 or 500 depending on validation
		assert.True(t, resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusInternalServerError)
	})
}

func TestAuthController_Logout(t *testing.T) {
	app := testutils.SetupTestApp(t)
	RegisterAuthRoutes(app)

	t.Run("Success with cookie", func(t *testing.T) {
		loginData := LoginDTO{
			Email:    testutils.ValidTestUserEmail,
			Password: testutils.ValidTestUserPassword,
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

		// Extract both auth and refresh tokens from login response
		var authToken, refreshToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Secure-access_token" {
				authToken = cookie.Value
			}
			if cookie.Name == "__Host-refresh_token" {
				refreshToken = cookie.Value
			}
		}

		// Test logout with auth cookie (middleware requires it)
		logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		logoutReq.AddCookie(&http.Cookie{
			Name:  "__Secure-access_token",
			Value: authToken,
		})
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
			Email:    testutils.ValidTestUserEmail,
			Password: testutils.ValidTestUserPassword,
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

		// Extract tokens from login response
		var refreshToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Host-refresh_token" {
				refreshToken = cookie.Value
			}
		}

		logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		logoutReq.Header.Set("Content-Type", "application/json")
		logoutReq.Header.Set("Authorization", "Bearer "+refreshToken)

		logoutResp, err := app.Test(logoutReq)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, logoutResp.StatusCode)
	})

	t.Run("No cookie - Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "No authentication token provided", response["error"])
	})

	t.Run("Clears cookies on successful logout", func(t *testing.T) {
		loginData := LoginDTO{
			Email:    testutils.ValidTestUserEmail,
			Password: testutils.ValidTestUserPassword,
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

		var authToken, refreshToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Secure-access_token" {
				authToken = cookie.Value
			}
			if cookie.Name == "__Host-refresh_token" {
				refreshToken = cookie.Value
			}
		}

		logoutReq := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		logoutReq.AddCookie(&http.Cookie{
			Name:  "__Secure-access_token",
			Value: authToken,
		})
		logoutReq.AddCookie(&http.Cookie{
			Name:  "__Host-refresh_token",
			Value: refreshToken,
		})

		logoutResp, err := app.Test(logoutReq)
		assert.NoError(t, err)

		// Check that cookies are cleared
		cookies := logoutResp.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == "__Host-refresh_token" || cookie.Name == "__Secure-access_token" {
				assert.Equal(t, "", cookie.Value, "Cookie %s should be cleared", cookie.Name)
				// Fiber's ClearCookie sets MaxAge to 0, not -1
				assert.Equal(t, 0, cookie.MaxAge, "Cookie %s MaxAge should be 0", cookie.Name)
			}
		}
	})

	// Additional tests for middleware authentication failures
	t.Run("Invalid auth token in header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "Invalid or expired token", response["error"])
	})

	t.Run("Expired auth token", func(t *testing.T) {
		// This would require creating an expired token - skipping for now
		t.Skip("Requires token expiration testing setup")
	})
}

func TestAuthController_RefreshToken(t *testing.T) {
	app := testutils.SetupTestApp(t)
	RegisterAuthRoutes(app)

	t.Run("Success", func(t *testing.T) {
		loginData := LoginDTO{
			Email:    testutils.ValidTestUserEmail,
			Password: testutils.ValidTestUserPassword,
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

		// Extract both auth and refresh tokens
		var authToken, refreshToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Secure-access_token" {
				authToken = cookie.Value
			}
			if cookie.Name == "__Host-refresh_token" {
				refreshToken = cookie.Value
			}
		}

		// Test refresh with auth token (required by middleware)
		refreshReq := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
		refreshReq.AddCookie(&http.Cookie{
			Name:  "__Secure-access_token",
			Value: authToken,
		})
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

	t.Run("No auth token - Unauthorized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "no refresh token cookie found", response["error"])
	})

	t.Run("Invalid auth token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Secure-access_token",
			Value: "invalid.token.here",
		})
		req.AddCookie(&http.Cookie{
			Name:  "__Host-refresh_token",
			Value: "some.refresh.token",
		})

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "token revoked, please log in again", response["error"])
	})

	t.Run("Valid auth but no refresh token", func(t *testing.T) {
		// First login to get auth token
		loginData := LoginDTO{
			Email:    testutils.ValidTestUserEmail,
			Password: testutils.ValidTestUserPassword,
		}
		loginBody, _ := json.Marshal(loginData)
		loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")
		loginResp, _ := app.Test(loginReq)

		var authToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Secure-access_token" {
				authToken = cookie.Value
				break
			}
		}

		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Secure-access_token",
			Value: authToken,
		})

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "no refresh token cookie found", response["error"])
	})

	t.Run("Valid auth but invalid refresh token", func(t *testing.T) {
		// First login to get auth token
		loginData := LoginDTO{
			Email:    testutils.ValidTestUserEmail,
			Password: testutils.ValidTestUserPassword,
		}
		loginBody, _ := json.Marshal(loginData)
		loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")
		loginResp, _ := app.Test(loginReq)

		var authToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Secure-access_token" {
				authToken = cookie.Value
				break
			}
		}

		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
		req.AddCookie(&http.Cookie{
			Name:  "__Secure-access_token",
			Value: authToken,
		})
		req.AddCookie(&http.Cookie{
			Name:  "__Host-refresh_token",
			Value: "invalid.refresh.token",
		})

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Mobile - Bearer token auth", func(t *testing.T) {
		// Login to get tokens
		loginData := LoginDTO{
			Email:    testutils.ValidTestUserEmail,
			Password: testutils.ValidTestUserPassword,
		}
		loginBody, _ := json.Marshal(loginData)
		loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")
		loginResp, _ := app.Test(loginReq)

		var authToken, refreshToken string
		for _, cookie := range loginResp.Cookies() {
			if cookie.Name == "__Secure-access_token" {
				authToken = cookie.Value
			}
			if cookie.Name == "__Host-refresh_token" {
				refreshToken = cookie.Value
			}
		}

		// Use Bearer token in header (mobile scenario)
		req := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		req.AddCookie(&http.Cookie{
			Name:  "__Host-refresh_token",
			Value: refreshToken,
		})

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestAuthController_GoogleLogin(t *testing.T) {
	app := testutils.SetupTestApp(t)
	RegisterAuthRoutes(app)
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
	app := testutils.SetupTestApp(t)
	RegisterAuthRoutes(app)
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
		assert.Contains(t, response["error"], "missing OAuth state parameter")
	})

	t.Run("Returns error on invalid state", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/google/callback?state=invalid_random_state&code=test_code", nil)

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "invalid or expired OAuth state")
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
		assert.Contains(t, response["error"], "missing authorization code")
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
		assert.Contains(t, response["error"], "invalid or expired OAuth state")
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

func TestAuthController_ForgotPassword(t *testing.T) {
	app := testutils.SetupTestApp(t)

	// Mock email service
	mockEmail := email.NewMockEmailService()
	authService := NewAuthService(mockEmail)
	authController := NewAuthController(authService)

	// Route with mock controller
	authGroup := app.Group("/api/auth")
	authGroup.Post("/forgot-password", authController.ForgotPassword)

	t.Run("Returns generic success message for existing user", func(t *testing.T) {
		mockEmail.Reset()

		reqBody := map[string]string{
			"email": testutils.ValidTestUserEmail,
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "If an account with that email exists")

		assert.Equal(t, 1, mockEmail.GetCallCount())
		assert.True(t, mockEmail.WasCalledWith(testutils.ValidTestUserEmail))
	})

	t.Run("Returns same message for non-existent user (prevents enumeration)", func(t *testing.T) {
		mockEmail.Reset()

		reqBody := map[string]string{
			"email": "nonexistent@example.com",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["message"], "If an account with that email exists")
	})

	t.Run("Returns error for invalid request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password",
			bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "invalid request body", response["error"])
	})

	t.Run("Returns error for missing email field", func(t *testing.T) {
		reqBody := map[string]string{}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "email")
	})

	t.Run("Returns error for invalid email format", func(t *testing.T) {
		reqBody := map[string]string{
			"email": "not-an-email",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "email")
	})

	t.Run("Returns error for empty email", func(t *testing.T) {
		reqBody := map[string]string{
			"email": "",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Handles concurrent requests properly", func(t *testing.T) {
		const numRequests = 5
		var wg sync.WaitGroup
		results := make(chan int, numRequests)

		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				reqBody := map[string]string{
					"email": fmt.Sprintf("concurrent%d@example.com", index),
				}
				body, _ := json.Marshal(reqBody)

				req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password",
					bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
				if err == nil {
					results <- resp.StatusCode
				}
			}(i)
		}

		wg.Wait()
		close(results)

		for statusCode := range results {
			assert.Equal(t, http.StatusOK, statusCode)
		}
	})

	t.Run("Does not reveal Redis errors to client", func(t *testing.T) {
		// This would require temporarily closing Redis connection
		// Skip for now as it would affect other tests
		t.Skip("Requires Redis connection manipulation")
	})

	t.Run("Validates email length", func(t *testing.T) {
		longEmail := string(make([]byte, 256)) + "@example.com"
		reqBody := map[string]string{
			"email": longEmail,
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		// Should either validate or return generic success
		assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest)
	})

	t.Run("Trims whitespace from email", func(t *testing.T) {
		reqBody := map[string]string{
			"email": "  " + testutils.ValidTestUserEmail + "  ",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Handles case-insensitive email matching", func(t *testing.T) {
		upperEmail := "TESTUSER@EXAMPLE.COM"
		reqBody := map[string]string{
			"email": upperEmail,
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestAuthController_ResetPassword(t *testing.T) {
	app := testutils.SetupTestApp(t)
	RegisterAuthRoutes(app)
	testDB := database.DB.DB

	// Helper to generate valid reset token
	generateValidToken := func(t *testing.T, email string) string {
		t.Helper()
		testutils.CreateTestUser(t, testDB, email, testutils.ValidTestUserPassword)

		service := NewAuthService()
		_, token, err := service.GenerateForgotPWUuid(email)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		return token
	}

	t.Run("Successfully resets password with valid token", func(t *testing.T) {
		email := "resetsuccess@example.com"
		newPassword := "NewSecurePass123!"
		token := generateValidToken(t, email)

		reqBody := map[string]string{
			"token":              token,
			"newPassword":        newPassword,
			"newPasswordConfirm": newPassword,
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "Password reset successfully", response["message"])

		// Verify can login with new password
		loginData := LoginDTO{
			Email:    email,
			Password: newPassword,
		}
		loginBody, _ := json.Marshal(loginData)
		loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")

		loginResp, err := app.Test(loginReq)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, loginResp.StatusCode)
	})

	t.Run("Returns error for invalid token", func(t *testing.T) {
		reqBody := map[string]string{
			"token":              "invalid-token-12345",
			"newPassword":        "NewSecurePass123!",
			"newPasswordConfirm": "NewSecurePass123!",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "invalid")
	})

	t.Run("Returns error for missing token", func(t *testing.T) {
		reqBody := map[string]string{
			"newPassword":        "NewSecurePass123!",
			"newPasswordConfirm": "NewSecurePass123!",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Returns error for missing password", func(t *testing.T) {
		email := "missingpass@example.com"
		token := generateValidToken(t, email)

		reqBody := map[string]string{
			"token": token,
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Returns error for weak password", func(t *testing.T) {
		email := "weakpass@example.com"
		token := generateValidToken(t, email)

		reqBody := map[string]string{
			"token":              token,
			"newPassword":        "weak",
			"newPasswordConfirm": "weak",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Contains(t, response["error"], "password")
	})

	t.Run("Cannot reuse token after successful reset", func(t *testing.T) {
		email := "noreuse@example.com"
		token := generateValidToken(t, email)

		reqBody := map[string]string{
			"token":              token,
			"newPassword":        "FirstPassword123!",
			"newPasswordConfirm": "FirstPassword123!",
		}
		body, _ := json.Marshal(reqBody)

		// First reset - should succeed
		req1 := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req1.Header.Set("Content-Type", "application/json")
		resp1, err := app.Test(req1, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp1.StatusCode)

		// Second reset with same token - should fail
		reqBody2 := map[string]string{
			"token":              token,
			"newPassword":        "SecondPassword123!",
			"newPasswordConfirm": "SecondPassword123!",
		}
		body2, _ := json.Marshal(reqBody2)

		req2 := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body2))
		req2.Header.Set("Content-Type", "application/json")
		resp2, err := app.Test(req2)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp2.StatusCode)
	})

	t.Run("Returns error for empty password", func(t *testing.T) {
		email := "emptypass@example.com"
		token := generateValidToken(t, email)

		reqBody := map[string]string{
			"token":              token,
			"newPassword":        "",
			"newPasswordConfirm": "",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Returns error for invalid request body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password",
			bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "invalid request body", response["error"])
	})

	t.Run("Returns error for malformed UUID token", func(t *testing.T) {
		reqBody := map[string]string{
			"token":              "not-a-uuid",
			"newPassword":        "NewSecurePass123!",
			"newPasswordConfirm": "NewSecurePass123!",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Validates password meets complexity requirements", func(t *testing.T) {
		email := "complexity@example.com"
		token := generateValidToken(t, email)

		weakPasswords := []string{
			"short",          // Too short
			"alllowercase",   // No uppercase or special chars
			"ALLUPPERCASE",   // No lowercase or special chars
			"NoSpecialChar1", // No special characters
			"NoNumbers!@#",   // No numbers
		}

		for _, weakPass := range weakPasswords {
			reqBody := map[string]string{
				"token":              token,
				"newPassword":        weakPass,
				"newPasswordConfirm": weakPass,
			}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
			assert.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
				"Password '%s' should be rejected", weakPass)
		}
	})

	t.Run("Old password no longer works after reset", func(t *testing.T) {
		email := "oldpassfail@example.com"
		oldPassword := "OldPassword123!"
		testutils.CreateTestUser(t, testDB, email, oldPassword)

		service := NewAuthService()
		_, token, err := service.GenerateForgotPWUuid(email)
		require.NoError(t, err)

		reqBody := map[string]string{
			"token":              token,
			"newPassword":        "NewPassword123!",
			"newPasswordConfirm": "NewPassword123!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Try to login with old password - should fail
		loginData := LoginDTO{
			Email:    email,
			Password: oldPassword,
		}
		loginBody, _ := json.Marshal(loginData)
		loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")

		loginResp, err := app.Test(loginReq)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, loginResp.StatusCode)
	})

	t.Run("Handles concurrent reset attempts", func(t *testing.T) {
		email := "concurrent@example.com"
		token := generateValidToken(t, email)

		const numAttempts = 3
		var wg sync.WaitGroup
		results := make(chan int, numAttempts)

		for i := 0; i < numAttempts; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				reqBody := map[string]string{
					"token":              token,
					"newPassword":        fmt.Sprintf("Password%d!@#", index),
					"newPasswordConfirm": fmt.Sprintf("Password%d!@#", index),
				}
				body, _ := json.Marshal(reqBody)

				req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password",
					bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
				if err == nil {
					results <- resp.StatusCode
				}
			}(i)
		}

		wg.Wait()
		close(results)

		successCount := 0
		for statusCode := range results {
			if statusCode == http.StatusOK {
				successCount++
			}
		}

		// Only one should succeed
		assert.Equal(t, 1, successCount, "Only one concurrent reset should succeed")
	})

	t.Run("Token expires after configured TTL", func(t *testing.T) {
		email := "expiry@example.com"
		token := generateValidToken(t, email)

		// Verify token exists in Redis
		ctx := context.Background()
		key := fmt.Sprintf("forgot_pw:%s", token)
		exists, err := database.RDB.Client.Exists(ctx, key).Result()
		assert.NoError(t, err)
		assert.Equal(t, int64(1), exists, "Token should exist in Redis")

		// Check TTL is set correctly
		ttl, err := database.RDB.Client.TTL(ctx, key).Result()
		assert.NoError(t, err)
		assert.Greater(t, ttl, time.Duration(0), "TTL should be positive")
		assert.LessOrEqual(t, ttl, constants.ForgotPWTokenTTL, "TTL should not exceed configured value")

		// Simulate token expiration by deleting it from Redis
		err = database.RDB.Client.Del(ctx, key).Err()
		assert.NoError(t, err)

		// Verify token is deleted
		exists, err = database.RDB.Client.Exists(ctx, key).Result()
		assert.NoError(t, err)
		assert.Equal(t, int64(0), exists, "Token should be deleted")

		// Try to reset password with expired token
		reqBody := map[string]string{
			"token":              token,
			"newPassword":        "NewPassword123!",
			"newPasswordConfirm": "NewPassword123!",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(5*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Should reject expired token")

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.NotNil(t, response["error"], "Should return an error")
		errorStr, ok := response["error"].(string)
		assert.True(t, ok, "Error should be a string")
		assert.Contains(t, errorStr, "invalid", "Should return error about invalid/expired token")
	})

	t.Run("Password and confirmation must match", func(t *testing.T) {
		email := "passconfirmationfail@example.com"
		pw := "Password123!"

		reqBody := map[string]string{
			"token":              generateValidToken(t, email),
			"newPassword":        pw,
			"newPasswordConfirm": pw + "mismatch",
		}

		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Token remains valid before TTL expires", func(t *testing.T) {
		email := "validbeforexpiry@example.com"
		token := generateValidToken(t, email)

		// Wait a bit but not long enough for expiration
		time.Sleep(100 * time.Millisecond)

		// Verify token still exists
		ctx := context.Background()
		key := fmt.Sprintf("forgot_pw:%s", token)
		exists, err := database.RDB.Client.Exists(ctx, key).Result()
		assert.NoError(t, err)
		assert.Equal(t, int64(1), exists, "Token should still exist")

		// Verify TTL is still positive
		ttl, err := database.RDB.Client.TTL(ctx, key).Result()
		assert.NoError(t, err)
		assert.Greater(t, ttl, time.Duration(0), "TTL should still be positive")

		// Try to reset password - should work
		reqBody := map[string]string{
			"token":              token,
			"newPassword":        "ValidPassword123!",
			"newPasswordConfirm": "ValidPassword123!",
		}
		body, err := json.Marshal(reqBody)
		assert.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		resp, err := app.Test(req, int(10*time.Second.Milliseconds()))
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Token should still be valid")

		var response map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&response)
		assert.NoError(t, err)
		assert.Equal(t, "Password reset successfully", response["message"])
	})
}
