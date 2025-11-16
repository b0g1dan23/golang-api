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
	googleClientId := os.Getenv("GOOGLE_CLIENT_ID")
	googleSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	if googleClientId != "" && googleSecret != "" {
		authGroup.Get("/google/login", controller.GoogleLogin)
		authGroup.Get("/google/callback", controller.GoogleCallback)
	}
	authGroup.Post("/register", controller.RegisterUser)

	protected := authGroup.Group("", middleware.RequireRoles("user"))
	protected.Post("/logout", controller.Logout)
	protected.Post("/refresh", controller.RefreshToken)
}
