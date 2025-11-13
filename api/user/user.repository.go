package user

import (
	"errors"

	database "boge.dev/golang-api/db"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserRepository struct {
	DB *gorm.DB
}

func NewUserRepository() *UserRepository {
	return &UserRepository{DB: database.DB.DB}
}

func (r *UserRepository) Create(user *User) (*User, error) {
	if err := r.DB.Clauses(clause.Returning{}).Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) FindByID(id string) (*User, error) {
	var user User
	if err := r.DB.First(&user, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByEmail(email string) (*User, error) {
	var user User
	if err := r.DB.First(&user, "email = ?", email).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("user with that email not found")
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindAll() ([]User, error) {
	var users []User
	if err := r.DB.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (r *UserRepository) Update(user *User) (*User, error) {
	if err := r.DB.Save(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) Delete(id string) error {
	if err := r.DB.Delete(&User{}, "id = ?", id).Error; err != nil {
		return err
	}
	return nil
}
