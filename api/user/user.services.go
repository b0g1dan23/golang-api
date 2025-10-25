package user

import (
	"errors"
	"fmt"

	database "boge.dev/golang-api/db"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserService struct {
	DB *gorm.DB
}

func NewUserService() *UserService {
	return &UserService{DB: database.DB.DB}
}

func (s *UserService) CreateUser(user *User) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user.Password = string(hashedPassword)

	if err := s.DB.Clauses(clause.Returning{}).Create(user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserService) GetUserByID(id string) (*User, error) {
	var user User
	if err := s.DB.First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("User with that ID not found")
		}
		return nil, err
	}
	return &user, nil
}

func (s *UserService) GetAllUsers() ([]User, error) {
	var users []User
	if err := s.DB.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (s *UserService) GetUserByEmail(email string) (*User, error) {
	var user User
	if err := s.DB.First(&user, "email = ?", email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("User with that email not found")
		}
		return nil, err
	}
	return &user, nil
}

func (s *UserService) ChangePassword(newPassword string, userID string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	return s.DB.Model(&User{}).Where("id = ?", userID).Update("password", string(hashedPassword)).Error
}

func (s *UserService) DeleteUser(userID string) error {
	return s.DB.Delete(&User{}, "id = ?", userID).Error
}
