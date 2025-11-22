package user

import (
	"boge.dev/golang-api/middleware"
	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(app *fiber.App) {
	controller := NewUserController()

	// User routes - any authenticated user can access their own profile
	userGroup := app.Group("/api/users", middleware.RequireRoles("user", "admin", "owner"))
	userGroup.Get("/me", controller.LoggedUser)

	// Admin/Owner routes - only admin and owner can access all users
	protectedGroup := app.Group("/api/users", middleware.RequireRoles("admin", "owner"))
	protectedGroup.Get("/", controller.GetAllUsers)
	protectedGroup.Get("/email", controller.GetUserByEmail)
	protectedGroup.Get("/:id", controller.GetUserByID)
	protectedGroup.Delete("/:id", controller.DeleteUser)
}
