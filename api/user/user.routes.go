package user

import (
	"boge.dev/golang-api/middleware"
	"github.com/gofiber/fiber/v2"
)

func RegisterRoutes(app *fiber.App) {
	controller := NewUserController()
	users := app.Group("/api/users")
	users.Get("/", middleware.RequireRoles("admin", "owner"), controller.GetAllUsers)
	users.Get("/:id", middleware.RequireRoles("admin", "owner"), controller.GetUserByID)
	users.Get("/email", middleware.RequireRoles("admin", "owner"), controller.GetUserByEmail)
	users.Delete("/:id", middleware.RequireRoles("admin", "owner"), controller.DeleteUser)
}
