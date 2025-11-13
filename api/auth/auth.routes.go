package auth

import (
	"os"

	"github.com/gofiber/fiber/v2"
)

func RegisterAuthRoutes(app *fiber.App) {
	controller := NewAuthController()
	auth := app.Group("/api/auth")
	auth.Post("/login", controller.Login)
	auth.Post("/logout", controller.Logout)
	auth.Post("/refresh", controller.RefreshToken)
	auth.Post("/register", controller.RegisterUser)

	google_client_id := os.Getenv("GOOGLE_CLIENT_ID")
	google_secret := os.Getenv("GOOGLE_CLIENT_SECRET")
	if google_client_id != "" && google_secret != "" {
		auth.Get("/google/login", controller.GoogleLogin)
		auth.Get("/google/callback", controller.GoogleCallback)
	}
}
