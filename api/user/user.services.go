package user

import (
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	repo *UserRepository
}

func NewUserService() *UserService {
	return &UserService{repo: NewUserRepository()}
}

func (s *UserService) CreateUser(user *User) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	user.Password = string(hashedPassword)

	return s.repo.Create(user)
}

func (s *UserService) GetUserByID(id string) (*User, error) {
	return s.repo.FindByID(id)
}

func (s *UserService) GetAllUsers() ([]User, error) {
	return s.repo.FindAll()
}

func (s *UserService) GetUserByEmail(email string) (*User, error) {
	return s.repo.FindByEmail(email)
}

func (s *UserService) ChangePassword(newPassword string, userID string) (*User, error) {
	user, err := s.repo.FindByID(userID)
	if err != nil {
		return nil, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user.Password = string(hashedPassword)
	updatedUser, err := s.repo.Update(user)
	return updatedUser, err
}

func (s *UserService) DeleteUser(userID string) error {
	return s.repo.Delete(userID)
}
