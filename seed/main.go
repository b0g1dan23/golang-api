package main

import (
	"log"
	"os"

	"boge.dev/golang-api/api/user"
	database "boge.dev/golang-api/db"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func main() {
	database.ConnectDB()

	if err := database.DB.DB.AutoMigrate(&user.User{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	db := database.DB

	var admin user.User
	err := db.DB.Where("role = ?", "admin").First(&admin).Error
	if err == nil {
		log.Println("Admin user already exists, skipping seeding")
		return
	} else if err != gorm.ErrRecordNotFound {
		log.Fatalf("Failed to query admin user: %v", err)
	}

	password, err := bcrypt.GenerateFromPassword([]byte(os.Getenv("ADMIN_PASSWORD")), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash admin password: %v", err)
	}
	admin = user.User{
		FirstName: os.Getenv("ADMIN_USERNAME"),
		LastName:  "Admin",
		Email:     os.Getenv("ADMIN_EMAIL"),
		Password:  string(password),
		Role:      "admin",
	}

	if err := db.DB.Create(&admin).Error; err != nil {
		log.Fatalf("Failed to seed admin user: %v", err)
	}

	log.Println("Admin user seeded successfully")
}
