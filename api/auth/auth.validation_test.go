package auth

import (
	"testing"

	database "boge.dev/golang-api/db"
	"boge.dev/golang-api/utils/testutils"
	"github.com/stretchr/testify/assert"
)

func TestLoginValidation(t *testing.T) {
	testutils.SetupTestConfig(t)
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB

	service := NewAuthService()

	t.Run("EmptyEmail", func(t *testing.T) {
		_, err := service.Login(LoginDTO{
			Email:    "",
			Password: "password",
		})

		assert.Error(t, err, "Login should fail for empty email")
		assert.ErrorIs(t, err, ErrEmptyEmail, "Should return empty email error")
	})

	t.Run("EmptyPassword", func(t *testing.T) {
		_, err := service.Login(LoginDTO{
			Email:    "test@example.com",
			Password: "",
		})

		assert.Error(t, err, "Login should fail for empty password")
		assert.ErrorIs(t, err, ErrEmptyPassword, "Should return empty password error")
	})

	t.Run("InvalidEmailFormat", func(t *testing.T) {
		invalidEmails := []string{
			"notanemail",
			"missing@domain",
			"@nodomain.com",
			"spaces in@email.com",
			"double@@domain.com",
		}

		for _, email := range invalidEmails {
			t.Run(email, func(t *testing.T) {
				_, err := service.Login(LoginDTO{
					Email:    email,
					Password: "password123",
				})

				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidEmailFormat, "Should return invalid email format error for: %s", email)
			})
		}
	})

	t.Run("WeakPassword", func(t *testing.T) {
		weakPasswords := []string{
			"short",
			"alllowercase",
			"ALLUPPERCASE",
			"12345678",
		}

		for _, pwd := range weakPasswords {
			t.Run(pwd, func(t *testing.T) {
				_, err := service.Login(LoginDTO{
					Email:    "test@example.com",
					Password: pwd,
				})

				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrPasswordTooWeak, "Should reject weak password: %s", pwd)
			})
		}
	})
}
