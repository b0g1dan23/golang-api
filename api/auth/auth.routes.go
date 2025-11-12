package auth

import "github.com/gofiber/fiber/v2"

func RegisterAuthRoutes(app *fiber.App) {
	controller := NewAuthController()
	auth := app.Group("/api/auth")
	auth.Post("/login", controller.Login)
	auth.Post("/logout", controller.Logout)
	auth.Post("/refresh", controller.RefreshToken)

	auth.Get("/google/login", controller.GoogleLogin)
	auth.Get("/google/callback", controller.GoogleCallback)
}
