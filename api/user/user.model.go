package user

import "boge.dev/golang-api/base"

type User struct {
	FirstName string `gorm:"type:varchar(100);not null" json:"firstname"`
	LastName  string `gorm:"type:varchar(100);not null" json:"lastname"`
	Email     string `gorm:"type:varchar(100);uniqueIndex;not null" json:"email"`
	Password  string `gorm:"type:varchar(255);not null" json:"-"`
	Role      string `gorm:"type:varchar(100);not null;default:'user'" json:"role"`
	base.BaseModel
}
