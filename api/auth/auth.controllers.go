package auth

import (
	"fmt"
	"net/http"
	"os"
	"time"

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
		RedirectURL:  "http://localhost:8080/api/auth/google/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
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

	setCookie(ctx, CookieData{
		Name:  "__Secure-auth_token",
		Value: loginRes.AuthToken,
	})
	setCookie(ctx, CookieData{
		Name:  "__Host-refresh_token",
		Value: loginRes.RefreshToken,
	})

	err = database.RDB.Client.Set(ctx.Context(),
		fmt.Sprintf("refresh_token:%s:%s", loginRes.User.ID, loginRes.RefreshJTI),
		loginRes.RefreshToken,
		constants.MaxRefreshTokenAge).Err()
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to store refresh token",
		})
	}

	return ctx.Status(http.StatusOK).JSON(fiber.Map{
		"user": loginRes.User,
	})
}

func (c *AuthController) Logout(ctx *fiber.Ctx) error {
	refreshCookie := ctx.Cookies("__Host-refresh_token")
	if refreshCookie == "" {
		ctx.ClearCookie("__Host-refresh_token")
		ctx.ClearCookie("__Secure-auth_token")
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "No refresh token cookie found",
		})
	}

	err := c.AuthService.Logout(refreshCookie)
	if err != nil {
		return ctx.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	ctx.ClearCookie("__Host-refresh_token")
	ctx.ClearCookie("__Secure-auth_token")

	return ctx.SendStatus(fiber.StatusNoContent)
}

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
		"user": loginRes.User,
	})
}

func (c *AuthController) GoogleLogin(ctx *fiber.Ctx) error {
	googleOAuthConfig := GetGoogleOAuthConfig()
	oauthStateString := os.Getenv("GOOGLE_STATE")
	url := googleOAuthConfig.AuthCodeURL(oauthStateString)
	fmt.Println(os.Getenv("GOOGLE_CLIENT_ID"))
	return ctx.Redirect(url)
}

func (c *AuthController) GoogleCallback(ctx *fiber.Ctx) error {
	oauthStateString := os.Getenv("GOOGLE_STATE")
	state := ctx.Query("state")
	if state != oauthStateString {
		return ctx.Status(fiber.StatusUnauthorized).SendString("Invalid OAuth state")
	}

	googleOAuthConfig := GetGoogleOAuthConfig()

	code := ctx.Query("code")
	user, err := c.AuthService.ExchangeCodeAndGetUser(code, googleOAuthConfig)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.JSON(user)
}
