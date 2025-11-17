package auth

import (
	"boge.dev/golang-api/api/user"
	"github.com/golang-jwt/jwt/v5"
)

type LoginDTO struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	ClientIP string `json:"-"` // Not from request body, set by controller
}

type RegisterDTO struct {
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=6"`
	FirstName string `json:"firstname" binding:"required"`
	LastName  string `json:"lastname" binding:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type OAuthLoginDTO struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type JWTData struct {
	ID    string    `json:"sub"`
	Email string    `json:"email"`
	Role  user.Role `json:"role"`
	JTI   string    `json:"jti,omitempty"`

	jwt.RegisteredClaims
}

type LoginResponse struct {
	AuthToken    string     `json:"authToken"`
	RefreshToken string     `json:"refreshToken"`
	User         *user.User `json:"user"`
	RefreshJTI   string     `json:"-"`
}

type CookieData struct {
	Name  string
	Value string
}

type ForgotPasswordDTO struct {
	Email string `json:"email" binding:"required,email"`
}

type ResetPasswordDTO struct {
	Token              string `json:"token" binding:"required"`
	NewPassword        string `json:"newPassword" binding:"required,min=6"`
	NewPasswordConfirm string `json:"newPasswordConfirm" binding:"required,eqfield=NewPassword"`
}
