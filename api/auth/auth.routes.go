package auth

import (
	"os"

	"boge.dev/golang-api/middleware"
	"github.com/gofiber/fiber/v2"
)

func RegisterAuthRoutes(app *fiber.App) {
	controller := NewAuthController()
	authGroup := app.Group("/api/auth")
	authGroup.Post("/login", controller.Login)
	authGroup.Post("/forgot-password", controller.ForgotPassword)
	authGroup.Post("/reset-password", controller.ResetPassword)
	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	googleSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	if googleClientId != "" && googleSecret != "" {
		authGroup.Get("/google/login", controller.GoogleLogin)
		authGroup.Get("/google/callback", controller.GoogleCallback)
	}
	authGroup.Post("/register", controller.RegisterUser)
	authGroup.Post("/refresh", controller.RefreshToken)
	authGroup.Post("/parse-jwt", controller.ParseJWT)

	protected := authGroup.Group("", middleware.RequireRoles("user", "admin", "owner"))
	protected.Post("/logout", controller.Logout)
}
