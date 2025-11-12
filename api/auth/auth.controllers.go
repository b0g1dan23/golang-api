package auth

import (
	"fmt"
	"net/http"
	"time"

	"boge.dev/golang-api/constants"
	database "boge.dev/golang-api/db"
	"github.com/gofiber/fiber/v2"
)

type AuthController struct {
	AuthService *AuthService
}

func NewAuthController() *AuthController {
	return &AuthController{AuthService: NewAuthService()}
}

func setCookie(ctx *fiber.Ctx, data CookieData) {
	cookie := new(fiber.Cookie)
	cookie.Name = data.Name
	cookie.Value = data.Value
	cookie.HTTPOnly = true
	cookie.Secure = true
	cookie.SameSite = "Lax"
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
