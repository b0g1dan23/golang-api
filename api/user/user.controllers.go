package user

import (
	"net/http"

	"github.com/gofiber/fiber/v2"
)

type UserController struct {
	UserService *UserService
}

func NewUserController() *UserController {
	return &UserController{UserService: NewUserService()}
}

func (c *UserController) RegisterUser(ctx *fiber.Ctx) error {
	var user User

	if err := ctx.BodyParser(&user); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if _, err := c.UserService.CreateUser(&user); err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return ctx.Status(http.StatusCreated).JSON(user)
}

func (c *UserController) GetAllUsers(ctx *fiber.Ctx) error {
	users, err := c.UserService.GetAllUsers()
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	return ctx.Status(http.StatusOK).JSON(users)
}

func (c *UserController) GetUserByID(ctx *fiber.Ctx) error {
	id := ctx.Params("id")
	user, err := c.UserService.GetUserByID(id)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	return ctx.Status(http.StatusOK).JSON(user)
}

func (c *UserController) GetUserByEmail(ctx *fiber.Ctx) error {
	email := ctx.Query("email")
	user, err := c.UserService.GetUserByEmail(email)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	return ctx.Status(http.StatusOK).JSON(user)
}

func (c *UserController) DeleteUser(ctx *fiber.Ctx) error {
	id := ctx.Params("id")
	if err := c.UserService.DeleteUser(id); err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	return ctx.Status(http.StatusNoContent).JSON(nil)
}
