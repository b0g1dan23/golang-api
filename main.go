package main

import (
	"log"
	"os"

	"boge.dev/golang-api/api/auth"
	"boge.dev/golang-api/api/user"
	database "boge.dev/golang-api/db"
	_ "boge.dev/golang-api/docs"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/swagger"
)

// @title My SaaS API
// @version 1.0
// @description API documentation for my SaaS boilerplate
// @host localhost:8080
// @BasePath /api
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
func main() {
	database.ConnectDB()
	database.InitializeRedis()

	if err := database.DB.DB.AutoMigrate(&user.User{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	app := fiber.New()

	app.Use(logger.New(logger.Config{
		Format:     "[${time}] ${status} - ${latency} ${method} ${path}\n",
		TimeFormat: "2006-01-02 15:04:05",
		TimeZone:   "Europe/Belgrade",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins:     os.Getenv("FRONTEND_URL"),
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		ExposeHeaders:    "Content-Length",
		AllowCredentials: true,
	}))

	app.Get("/swagger/*", swagger.HandlerDefault)
	user.RegisterRoutes(app)
	auth.RegisterAuthRoutes(app)

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
