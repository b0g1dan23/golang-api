package auth

import "boge.dev/golang-api/api/user"

type LoginDTO struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
	ClientIP string `json:"-"` // Not from request body, set by controller
}

type JWTData struct {
	ID    string `json:"sub"`
	Email string `json:"email"`
	Role  string `json:"role"`
	JTI   string `json:"jti,omitempty"`
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
