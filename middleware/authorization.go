package middleware

import (
	"fmt"
	"os"
	"strings"

	"boge.dev/golang-api/api/auth"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func RequireRoles(allowedRoles ...string) fiber.Handler {
	jwtSecret := os.Getenv("JWT_SECRET")

	if jwtSecret == "" {
		// Return an error handler that always fails
		return func(ctx *fiber.Ctx) error {
			return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Server configuration error",
			})
		}
	}

	return func(ctx *fiber.Ctx) error {
		authHeader := ctx.Get("Authorization")
		var tokenString string

		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			// Fallback to cookie (browser)
			tokenString = ctx.Cookies("__Secure-auth_token")
		}

		if tokenString == "" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "No authentication token provided",
			})
		}

		token, err := jwt.ParseWithClaims(tokenString, &auth.JWTData{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		claims, ok := token.Claims.(*auth.JWTData)
		if !ok {
			return ctx.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token claims",
			})
		}

		userRole := claims.Role
		hasRole := false
		for _, role := range allowedRoles {
			if userRole == role {
				hasRole = true
				break
			}
		}

		if !hasRole {
			return ctx.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": fmt.Sprintf("Access denied for role %s", userRole),
			})
		}

		// Store user info in context for later use
		ctx.Locals("userID", claims.ID)
		ctx.Locals("userRole", userRole)

		return ctx.Next()
	}
}
