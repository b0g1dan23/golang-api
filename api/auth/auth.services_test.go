package auth

import (
	"os"
	"testing"
	"time"

	database "boge.dev/golang-api/db"
	"boge.dev/golang-api/utils/testutils"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	os.Setenv("JWT_SECRET", "test-secret-at-least-32-chars")
	code := m.Run()
	os.Exit(code)
}

func TestAuthService_Login_Success(t *testing.T) {
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB

	email := "test@example.com"
	password := "testPassword123"

	testutils.CreateTestUser(t, testDB, email, password)

	service := NewAuthService()
	loginDTO := LoginDTO{
		Email:    email,
		Password: password,
	}

	result, err := service.Login(loginDTO)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be empty")
	}
	assert.Equal(t, email, result.User.Email, "Returned user email should match")
	claims := testutils.ParseJWTClaims(t, result.AuthToken)
	assert.Equal(t, result.User.ID, claims["sub"])
	assert.Equal(t, result.User.Email, claims["email"])
	assert.Equal(t, result.User.Role, claims["role"])
	assert.NotNil(t, claims["exp"])
	claims = testutils.ParseJWTClaims(t, result.RefreshToken)
	assert.Equal(t, result.User.ID, claims["sub"])
	assert.Equal(t, result.User.Email, claims["email"])
	assert.Equal(t, result.User.Role, claims["role"])
	assert.NotNil(t, claims["exp"])
}

func TestCreateJWTToken_Success(t *testing.T) {
	os.Setenv("JWT_SECRET", "testsecret")
	defer os.Unsetenv("JWT_SECRET")

	randUUID := uuid.New()
	data := JWTData{
		ID:    "123",
		Role:  "admin",
		Email: "admin@gmail.com",
		JTI:   randUUID.String(),
	}

	token, err := createJWTToken(data, time.Hour)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestCreateJWTToken_NoSecret(t *testing.T) {
	os.Unsetenv("JWT_SECRET") // sigurno da nije setovan

	randUUID := uuid.New()
	data := JWTData{
		ID:    "123",
		Role:  "admin",
		Email: "admin@gmail.com",
		JTI:   randUUID.String(),
	}

	token, err := createJWTToken(data, time.Hour)
	assert.Error(t, err)
	assert.Equal(t, "", token)
	assert.Equal(t, "JWT_SECRET environment variable not set", err.Error())
}

func TestCreateJWTToken_EmptyData(t *testing.T) {
	os.Setenv("JWT_SECRET", "testsecret")
	defer os.Unsetenv("JWT_SECRET")

	data := JWTData{}

	token, err := createJWTToken(data, time.Hour)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestCreateJWTToken_ZeroDuration(t *testing.T) {
	os.Setenv("JWT_SECRET", "testsecret")
	defer os.Unsetenv("JWT_SECRET")

	randUUID := uuid.New()
	data := JWTData{
		ID:    "123",
		Role:  "admin",
		Email: "admin@gmail.com",
		JTI:   randUUID.String(),
	}

	token, err := createJWTToken(data, 0)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	assert.Error(t, err)
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	assert.Equal(t, claims["exp"], claims["iat"])
}

func TestAuthService_Login_WrongPassword(t *testing.T) {
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB

	email := "test@example.com"
	testutils.CreateTestUser(t, testDB, email, "correctpassword")

	service := NewAuthService()
	loginDTO := LoginDTO{
		Email:    email,
		Password: "wrongpassword",
	}

	result, err := service.Login(loginDTO)

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB

	service := NewAuthService()
	loginDTO := LoginDTO{
		Email:    "nonexistent@example.com",
		Password: "anypassword",
	}

	result, err := service.Login(loginDTO)

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestAuthService_Login_DBError(t *testing.T) {
	database.DB.DB = testutils.SetupFailingDB(t)

	service := NewAuthService()
	_, err := service.Login(LoginDTO{
		Email:    "any@example.com",
		Password: "anypassword",
	})

	assert.Error(t, err, "Expected DB error")
}

func TestAuthService_Login_EmptyEmail(t *testing.T) {
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB

	service := NewAuthService()
	_, err := service.Login(LoginDTO{
		Email:    "",
		Password: "password",
	})

	assert.Error(t, err, "Login should fail for empty email")
}

func TestAuthService_Login_EmptyPassword(t *testing.T) {
	testDB := testutils.SetupTestDB(t)
	database.DB.DB = testDB

	service := NewAuthService()
	_, err := service.Login(LoginDTO{
		Email:    "test@example.com",
		Password: "",
	})

	assert.Error(t, err, "Login should fail for empty password")
}
