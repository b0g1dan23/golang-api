package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	user "boge.dev/golang-api/api/user"
	"boge.dev/golang-api/constants"
	database "boge.dev/golang-api/db"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type AuthController struct {
	AuthService *AuthService
}

func NewAuthController() *AuthController {
	return &AuthController{AuthService: NewAuthService()}
}

func GetGoogleOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  os.Getenv("APP_URL") + "/api/auth/google/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func saveUserInCookie(ctx *fiber.Ctx, loginRes *LoginResponse) error {
	// Store the refresh token in Redis
	err := database.RDB.Client.Set(ctx.Context(),
		fmt.Sprintf("refresh_token:%s:%s", loginRes.User.ID, loginRes.RefreshJTI),
		loginRes.RefreshToken,
		constants.MaxRefreshTokenAge).Err()
	if err != nil {
		return errors.New("failed to store refresh token")
	}

	// Set secure cookies
	setCookie(ctx, CookieData{
		Name:  "__Host-refresh_token",
		Value: loginRes.RefreshToken,
	})
	setCookie(ctx, CookieData{
		Name:  "__Secure-auth_token",
		Value: loginRes.AuthToken,
	})

	return nil
}

func generateOAuthState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func setCookie(ctx *fiber.Ctx, data CookieData) {
	cookie := new(fiber.Cookie)
	cookie.Name = data.Name
	cookie.Value = data.Value
	cookie.HTTPOnly = true
	cookie.Secure = os.Getenv("GO_ENV") != "development"
	cookie.SameSite = "Strict"
	cookie.Path = "/"
	cookie.MaxAge = int(constants.MaxLoginTokenAge / time.Second)

	ctx.Cookie(cookie)
}

// Login godoc
// @Summary      User login
// @Description  Authenticates user with email and password
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        login  body      LoginDTO  true  "Login credentials"
// @Success      200    {object}  map[string]interface{} "user, access_token, refresh_token"
// @Failure      400    {object}  map[string]string "Invalid request body"
// @Failure      401    {object}  map[string]string "Invalid credentials"
// @Failure      500    {object}  map[string]string "Internal server error"
// @Router       /auth/login [post]
func (c *AuthController) Login(ctx *fiber.Ctx) error {
	var loginData LoginDTO
	if err := ctx.BodyParser(&loginData); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Extract client IP
	loginData.ClientIP = ctx.IP()

	loginRes, err := c.AuthService.Login(loginData)
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	err = saveUserInCookie(ctx, loginRes)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(http.StatusOK).JSON(fiber.Map{
		"user":          loginRes.User,
		"access_token":  loginRes.AuthToken,
		"refresh_token": loginRes.RefreshToken,
	})
}

// Logout godoc
// @Summary      User logout
// @Description  Invalidates refresh token and clears auth cookies
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        refreshToken  body      LogoutRequest  false  "Refresh token (optional if cookie present)"
// @Success      204           "Successfully logged out"
// @Failure      400           {object}  map[string]string "No refresh token found"
// @Failure      401           {object}  map[string]string "Invalid token"
// @Router       /auth/logout [post]
// @Security     BearerAuth
func (c *AuthController) Logout(ctx *fiber.Ctx) error {
	refreshToken := ctx.Cookies("__Host-refresh_token")

	if refreshToken == "" {
		var refreshBody LogoutRequest

		if err := ctx.BodyParser(&refreshBody); err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "No refresh token found",
			})
		}

		if refreshBody.RefreshToken == "" {
			ctx.ClearCookie("__Host-refresh_token", "__Secure-auth_token")
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Refresh token not provided",
			})
		}

		refreshToken = refreshBody.RefreshToken
	}

	if err := c.AuthService.Logout(refreshToken); err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	ctx.ClearCookie("__Host-refresh_token", "__Secure-auth_token")

	return ctx.SendStatus(fiber.StatusNoContent)
}

// RefreshToken godoc
// @Summary      Refresh access token
// @Description  Generates new access and refresh tokens using a valid refresh token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Success      200  {object}  map[string]interface{} "user, access_token, refresh_token"
// @Failure      400  {object}  map[string]string "No refresh token cookie found"
// @Failure      401  {object}  map[string]string "Token revoked or invalid"
// @Failure      500  {object}  map[string]string "Failed to store refresh token"
// @Router       /auth/refresh [post]
// @Security     BearerAuth
func (c *AuthController) RefreshToken(ctx *fiber.Ctx) error {
	oldToken := ctx.Cookies("__Host-refresh_token")
	if oldToken == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "No refresh token cookie found",
		})
	}

	loginRes, err := c.AuthService.RefreshToken(oldToken)
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token revoked, please log in again",
		})
	}

	err = database.RDB.Client.Set(ctx.Context(),
		fmt.Sprintf("refresh_token:%s:%s", loginRes.User.ID, loginRes.RefreshJTI),
		loginRes.RefreshToken,
		constants.MaxRefreshTokenAge).Err()
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to store refresh token",
		})
	}

	setCookie(ctx, CookieData{
		Name:  "__Host-refresh_token",
		Value: loginRes.RefreshToken,
	})
	setCookie(ctx, CookieData{
		Name:  "__Secure-auth_token",
		Value: loginRes.AuthToken,
	})

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"user":          loginRes.User,
		"access_token":  loginRes.AuthToken,
		"refresh_token": loginRes.RefreshToken,
	})
}

// GoogleLogin godoc
// @Summary      Initiate Google OAuth login
// @Description  Redirects user to Google OAuth consent screen
// @Tags         auth
// @Produce      json
// @Success      302  "Redirects to Google OAuth"
// @Failure      500  {object}  map[string]string "Failed to generate OAuth state"
// @Router       /auth/google/login [get]
func (c *AuthController) GoogleLogin(ctx *fiber.Ctx) error {
	state, err := generateOAuthState()
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate OAuth state",
		})
	}

	err = database.RDB.Client.Set(ctx.Context(),
		fmt.Sprintf("oauth_state:%s", state),
		"1",
		10*time.Minute).Err()
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to store OAuth state",
		})
	}

	googleOAuthConfig := GetGoogleOAuthConfig()
	url := googleOAuthConfig.AuthCodeURL(state)
	return ctx.Redirect(url)
}

// GoogleCallback godoc
// @Summary      Google OAuth callback
// @Description  Handles Google OAuth callback and authenticates user
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        state  query     string  true  "OAuth state parameter"
// @Param        code   query     string  true  "OAuth authorization code"
// @Success      200    {object}  map[string]interface{} "user, access_token, refresh_token"
// @Failure      400    {object}  map[string]string "Missing OAuth state parameter or authorization code"
// @Failure      401    {object}  map[string]string "Invalid or expired OAuth state"
// @Failure      500    {object}  map[string]string "Internal server error"
// @Router       /auth/google/callback [get]
func (c *AuthController) GoogleCallback(ctx *fiber.Ctx) error {
	state := ctx.Query("state")
	if state == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing OAuth state parameter",
		})
	}

	exists, err := database.RDB.Client.Exists(ctx.Context(),
		fmt.Sprintf("oauth_state:%s", state)).Result()
	if err != nil || exists == 0 {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired OAuth state",
		})
	}

	database.RDB.Client.Del(ctx.Context(), fmt.Sprintf("oauth_state:%s", state))

	googleOAuthConfig := GetGoogleOAuthConfig()

	code := ctx.Query("code")
	if code == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	user, err := c.AuthService.ExchangeCodeAndGetUser(code, googleOAuthConfig)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	loginRes, err := c.AuthService.LoginOAuthUser(OAuthLoginDTO{
		Email: user.Email,
	})
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	err = saveUserInCookie(ctx, loginRes)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"user":          loginRes.User,
		"access_token":  loginRes.AuthToken,
		"refresh_token": loginRes.RefreshToken,
	})
}

// RegisterUser godoc
// @Summary      Register a new user
// @Description  Creates a new user account with provided information
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        user  body      RegisterDTO  true  "User registration data"
// @Success      201   {object}  user.User  "User created successfully"
// @Failure      400   {object}  map[string]string "Invalid request body"
// @Failure      500   {object}  map[string]string "Internal server error"
// @Router       /auth/register [post]
func (c *AuthController) RegisterUser(ctx *fiber.Ctx) error {
	var registerData RegisterDTO

	if err := ctx.BodyParser(&registerData); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Create user from DTO
	newUser := user.User{
		Email:     registerData.Email,
		Password:  registerData.Password,
		FirstName: registerData.FirstName,
		LastName:  registerData.LastName,
		Role:      user.RoleUser,
	}

	// Save original password for login (CreateUser will hash it)
	originalPassword := registerData.Password

	createdUser, err := c.AuthService.UserService.CreateUser(&newUser)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Use original password for login (not the hashed one)
	loginRes, err := c.AuthService.Login(LoginDTO{
		Email:    createdUser.Email,
		Password: originalPassword,
		ClientIP: ctx.IP(),
	})
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": fmt.Sprintf("Failed to generate tokens: %v", err),
		})
	}

	err = saveUserInCookie(ctx, loginRes)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(http.StatusCreated).JSON(createdUser)
}
