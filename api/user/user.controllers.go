package user

import (
	"errors"
	"net/http"

	"boge.dev/golang-api/api"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserController struct {
	UserService *UserService
}

func NewUserController() *UserController {
	return &UserController{UserService: NewUserService()}
}

// GetAllUsers godoc
// @Summary      Get all users
// @Description  Retrieves a list of all registered users
// @Tags         users
// @Accept       json
// @Produce      json
// @Success      200  {array}   User  "List of users"
// @Failure      500  {object}  api.ErrorResponse "Internal server error"
// @Router       /users [get]
// @Security     BearerAuth
func (c *UserController) GetAllUsers(ctx *fiber.Ctx) error {
	users, err := c.UserService.GetAllUsers()
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(&api.ErrorResponse{
			Error: err.Error(),
		})
	}
	return ctx.Status(http.StatusOK).JSON(users)
}

// GetUserByID godoc
// @Summary      Get user by ID
// @Description  Retrieves a specific user by their unique ID
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id   path      string  true  "User ID"
// @Success      200  {object}  User    "User found"
// @Failure      400  {object}  api.ErrorResponse "Invalid user ID"
// @Failure      404  {object}  api.ErrorResponse "User not found"
// @Failure      500  {object}  api.ErrorResponse "Internal server error"
// @Router       /users/{id} [get]
// @Security     BearerAuth
func (c *UserController) GetUserByID(ctx *fiber.Ctx) error {
	id := ctx.Params("id")

	if err := uuid.Validate(id); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(&api.ErrorResponse{
			Error: "invalid user ID format",
		})
	}

	user, err := c.UserService.GetUserByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ctx.Status(http.StatusNotFound).JSON(&api.ErrorResponse{
				Error: "user not found",
			})
		}
		return ctx.Status(http.StatusInternalServerError).JSON(&api.ErrorResponse{
			Error: err.Error(),
		})
	}
	return ctx.Status(http.StatusOK).JSON(user)
}

// GetUserByEmail godoc
// @Summary      Get user by email
// @Description  Retrieves a specific user by their email address
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        email  query     string  true  "User email"
// @Success      200    {object}  User    "User found"
// @Failure      400    {object}  api.ErrorResponse "Invalid email format"
// @Failure      404    {object}  api.ErrorResponse "User not found"
// @Failure      500    {object}  api.ErrorResponse "Internal server error"
// @Router       /users/by-email [get]
// @Security     BearerAuth
func (c *UserController) GetUserByEmail(ctx *fiber.Ctx) error {
	email := ctx.Query("email")
	user, err := c.UserService.GetUserByEmail(email)
	if err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(&api.ErrorResponse{
			Error: err.Error(),
		})
	}
	return ctx.Status(http.StatusOK).JSON(user)
}

// DeleteUser godoc
// @Summary      Delete user
// @Description  Deletes a user account by ID
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        id   path  	string  true  "User ID"
// @Success 	 204  {object} 	nil 	"No Content"
// @Failure      400  {object}  api.ErrorResponse "Invalid user ID"
// @Failure      404  {object}  api.ErrorResponse "User not found"
// @Failure      500  {object}  api.ErrorResponse "Internal server error"
// @Router       /users/{id} [delete]
// @Security     BearerAuth
func (c *UserController) DeleteUser(ctx *fiber.Ctx) error {
	id := ctx.Params("id")

	if err := uuid.Validate(id); err != nil {
		return ctx.Status(http.StatusBadRequest).JSON(&api.ErrorResponse{
			Error: "invalid user ID format",
		})
	}
	if _, err := c.UserService.GetUserByID(id); err != nil {
		return ctx.Status(http.StatusNotFound).JSON(&api.ErrorResponse{
			Error: "user not found",
		})
	}
	if err := c.UserService.DeleteUser(id); err != nil {
		return ctx.Status(http.StatusInternalServerError).JSON(&api.ErrorResponse{
			Error: err.Error(),
		})
	}
	return ctx.Status(http.StatusNoContent).JSON(nil)
}
