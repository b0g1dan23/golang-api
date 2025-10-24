package user

import "boge.dev/golang-api/base"

type User struct {
	ID        string `gorm:"type:uuid;default:gen_random_uuid();primaryKey" json:"id"`
	FirstName string `gorm:"type:varchar(100);not null" json:"firstname"`
	LastName  string `gorm:"type:varchar(100);not null" json:"lastname"`
	Email     string `gorm:"type:varchar(100);uniqueIndex;not null" json:"email"`
	Password  string `gorm:"type:varchar(255);not null" json:"-"`
	base.BaseModel
}
