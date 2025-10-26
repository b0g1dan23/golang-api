package auth

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"boge.dev/golang-api/constants"
	database "boge.dev/golang-api/db"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthController struct {
	AuthService *AuthService
}

func NewAuthController() *AuthController {
	return &AuthController{AuthService: NewAuthService()}
}

func parseJWT(tokenString string) (map[string]interface{}, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New("JWT_SECRET environment variable not set")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, errors.New("token expired")
		}
	}

	return claims, nil
}

func setCookie(ctx *fiber.Ctx, data CookieData) {
	cookie := new(fiber.Cookie)
	cookie.Name = data.Name
	cookie.Value = data.Value
	cookie.HTTPOnly = true
	cookie.Secure = os.Getenv("GO_ENV") == "production"
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

	database.RDB.Client.Set(ctx.Context(),
		fmt.Sprintf("refresh_token:%s:%s", loginRes.User.ID, loginRes.RefreshJTI),
		loginRes.RefreshToken,
		constants.MaxRefreshTokenAge)

	return ctx.Status(http.StatusOK).JSON(fiber.Map{
		"user": loginRes.User,
	})
}

func (c *AuthController) Logout(ctx *fiber.Ctx) error {
	refreshCookie := ctx.Cookies("__Host-refresh_token")
	if refreshCookie == "" {
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "No refresh token cookie found",
		})
	}

	claims, err := parseJWT(refreshCookie)
	if err == nil {
		jti, _ := claims["jti"].(string)
		userID, _ := claims["sub"].(string)
		if jti != "" && userID != "" {
			key := fmt.Sprintf("refresh_token:%s:%s", userID, jti)
			database.RDB.Client.Del(ctx.Context(), key)
		}
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

	claims, err := parseJWT(oldToken)
	if err != nil {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}

	userID, _ := claims["sub"].(string)
	oldJTI, _ := claims["jti"].(string)

	key := fmt.Sprintf("refresh_token:%s:%s", userID, oldJTI)
	exists, err := database.RDB.Client.Exists(ctx.Context(), key).Result()
	if err != nil || exists == 0 {
		return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Token revoked"})
	}

	database.RDB.Client.Del(ctx.Context(), key)

	newJTI := uuid.New().String()
	userData, _ := c.AuthService.UserService.GetUserByID(userID)

	refreshToken, _ := createJWTToken(JWTData{
		ID:    userData.ID,
		Email: userData.Email,
		Role:  userData.Role,
		JTI:   newJTI,
	}, constants.MaxRefreshTokenAge)

	authToken, _ := createJWTToken(JWTData{
		ID:    userData.ID,
		Email: userData.Email,
		Role:  userData.Role,
	}, constants.MaxLoginTokenAge)

	key = fmt.Sprintf("refresh_token:%s:%s", userID, newJTI)
	database.RDB.Client.Set(ctx.Context(), key, refreshToken, constants.MaxRefreshTokenAge)

	setCookie(ctx, CookieData{
		Name:  "__Host-refresh_token",
		Value: refreshToken,
	})
	setCookie(ctx, CookieData{
		Name:  "__Secure-auth_token",
		Value: authToken,
	})

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"user": userData,
	})
}
