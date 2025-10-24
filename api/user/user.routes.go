package user

import "github.com/gofiber/fiber/v2"

func RegisterRoutes(app *fiber.App) {
	controller := NewUserController()
	users := app.Group("/api/users")
	users.Post("/", controller.RegisterUser)
	users.Get("/", controller.GetAllUsers)
	users.Get("/:id", controller.GetUserByID)
	users.Get("/email", controller.GetUserByEmail)
	users.Delete("/:id", controller.DeleteUser)
}
