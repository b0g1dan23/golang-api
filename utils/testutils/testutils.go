package testutils

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"boge.dev/golang-api/api/user"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func SetupFailingDB(t *testing.T) *gorm.DB {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to open sqlmock database: %v", err)
	}

	gormDB, err := gorm.Open(postgres.New(postgres.Config{
		Conn: db,
	}), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to initialize gorm DB: %v", err)
	}

	mock.ExpectQuery("SELECT .").WillReturnError(errors.New("forced DB error"))

	return gormDB
}

func ParseJWTClaims(t *testing.T, tokenString string) jwt.MapClaims {
	t.Helper()

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		t.Fatal("JWT_SECRET environment variable not set")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		t.Fatalf("Failed to parse JWT token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to extract claims from JWT token")
	}

	if !token.Valid {
		t.Fatal("JWT token is invalid or expired")
	}

	return claims
}

func SetupTestDB(t *testing.T) *gorm.DB {
	if err := godotenv.Load("../../.env"); err != nil {
		t.Fatal("Failed to load .env file\n", err.Error())
	}
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Europe/Belgrade",
		os.Getenv("TEST_POSTGRES_HOST"),
		os.Getenv("TEST_POSTGRES_USER"),
		os.Getenv("TEST_POSTGRES_PASSWORD"),
		os.Getenv("TEST_POSTGRES_DB"),
		os.Getenv("TEST_POSTGRES_PORT"),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal("Failed to connect to test database\n", err.Error())
	}

	err = db.AutoMigrate(&user.User{})
	if err != nil {
		t.Fatal("Failed to migrate test database\n", err.Error())
	}

	t.Cleanup(func() {
		CleanupTestDB(t, db)
	})

	return db
}

func CleanupTestDB(t *testing.T, db *gorm.DB) {
	db.Exec("TRUNCATE users RESTART IDENTITY CASCADE")

	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.Close()
	}
}

func CreateTestUser(t *testing.T, db *gorm.DB, email, password string) *user.User {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal("Failed to hash password\n", err.Error())
	}

	testUser := &user.User{
		Email:     email,
		Password:  string(hashedPassword),
		FirstName: "Test",
		LastName:  "User",
		Role:      "user",
	}

	result := db.Create(testUser)
	if result.Error != nil {
		t.Fatal("Failed to create test user\n", result.Error.Error())
	}

	return testUser
}
