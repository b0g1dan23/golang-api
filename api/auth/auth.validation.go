package auth

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

func ValidateEmail(email string) error {
	if email == "" {
		return ErrEmptyEmail
	}
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmailFormat
	}
	return nil
}

func ValidatePassword(password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	if len(password) < 8 {
		return ErrPasswordTooWeak
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return ErrPasswordTooWeak
	}
	return nil
}

func ValidateLoginDTO(dto LoginDTO) error {
	if err := ValidateEmail(dto.Email); err != nil {
		return err
	}
	if err := ValidatePassword(dto.Password); err != nil {
		return err
	}
	return nil
}

func ValidateOAuthLoginDTO(dto OAuthLoginDTO) error {
	if dto.Email == "" {
		return errors.New("email is required")
	}

	if dto.FirstName == "" {
		return errors.New("first name is required")
	}

	if dto.LastName == "" {
		return errors.New("last name is required")
	}

	// Basic email validation
	if !strings.Contains(dto.Email, "@") {
		return errors.New("invalid email format")
	}

	return nil
}
