package testutils

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"boge.dev/golang-api/api/user"
	database "boge.dev/golang-api/db"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	testConfigMutex = &sync.Mutex{}
	originalEnv     map[string]string
)

func SetupTestConfig(t *testing.T) {
	t.Helper()
	testConfigMutex.Lock()

	originalEnv = map[string]string{
		"JWT_SECRET":             os.Getenv("JWT_SECRET"),
		"GO_ENV":                 os.Getenv("GO_ENV"),
		"TEST_POSTGRES_HOST":     os.Getenv("TEST_POSTGRES_HOST"),
		"TEST_POSTGRES_USER":     os.Getenv("TEST_POSTGRES_USER"),
		"TEST_POSTGRES_PASSWORD": os.Getenv("TEST_POSTGRES_PASSWORD"),
		"TEST_POSTGRES_DB":       os.Getenv("TEST_POSTGRES_DB"),
		"TEST_POSTGRES_PORT":     os.Getenv("TEST_POSTGRES_PORT"),
	}

	jwtSecret := generateSecureTestSecret(t)

	os.Setenv("JWT_SECRET", jwtSecret)
	os.Setenv("GO_ENV", "test")

	t.Cleanup(func() {
		for key, val := range originalEnv {
			if val == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, val)
			}
		}
		testConfigMutex.Unlock()
	})
}

func RestoreTestJWTSecret(t *testing.T) {
	t.Helper()
	jwtSecret := generateSecureTestSecret(t)
	os.Setenv("JWT_SECRET", jwtSecret)
}

func ValidateJWTSecret(secret string) error {
	if secret == "" {
		return fmt.Errorf("JWT_SECRET is empty")
	}

	if len(secret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters long")
	}

	weakSecrets := []string{
		"secret",
		"test",
		"password",
		"12345678",
		"test-secret",
		"your-test-secret-key",
	}

	for _, weak := range weakSecrets {
		if secret == weak {
			return fmt.Errorf("JWT_SECRET is too weak")
		}
	}

	return nil
}

func generateSecureTestSecret(t *testing.T) string {
	t.Helper()

	secretBytes := make([]byte, 32)
	_, err := rand.Read(secretBytes)
	if err != nil {
		t.Fatalf("Failed to generate secure test JWT secret: %v", err)
	}

	return base64.StdEncoding.EncodeToString(secretBytes)
}

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

func ParseJWTClaimsAllowExpired(t *testing.T, tokenString string) (jwt.MapClaims, error) {
	t.Helper()

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable not set")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	}, jwt.WithoutClaimsValidation())

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to extract claims from JWT token")
	}

	return claims, nil
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

	tx := db.Begin()
	if tx.Error != nil {
		t.Fatal("Failed to begin transaction for test database\n", tx.Error.Error())
	}

	t.Cleanup(func() {
		if err := tx.Rollback().Error; err != nil {
			t.Logf("Warning: Failed to rollback transaction: %v", err)
		}

		CleanupTestDB(t, db)

		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.Close()
		}
	})

	return tx
}

func SetupTestRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("Failed to start miniredis: %v", err)
	}

	client := redis.NewClient(&redis.Options{
		Addr:         mr.Addr(),
		Password:     "",
		DB:           0,
		DialTimeout:  10 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		PoolSize:     10,
		PoolTimeout:  30 * time.Second,
	})

	if database.RDB == nil {
		database.RDB = &database.RedisInstance{}
	}

	database.RDB.Client = client

	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("Warning: Failed to close Redis client: %v", err)
		}
		mr.Close()
	})

	return mr
}

func ClearRateLimitKeys(email string) {
	ctx := context.Background()

	keys := []string{
		fmt.Sprintf("login_attempts:%s", email),
		fmt.Sprintf("account_locked:%s", email),
	}

	for _, key := range keys {
		database.RDB.Client.Del(ctx, key)
	}
}

func CleanupTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()

	tables := []string{"users"}

	for _, table := range tables {
		result := db.Exec(fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table))
		if result.Error != nil {
			t.Logf("Warning: Failed to truncate %s: %v", table, result.Error)
		}
	}
}

func CreateTestUser(t *testing.T, db *gorm.DB, email, password string) *user.User {
	t.Helper()

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
