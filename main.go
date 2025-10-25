package main

import (
	"os"

	"boge.dev/golang-api/api/user"
	database "boge.dev/golang-api/db"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func main() {
	database.ConnectDB()
	database.InitializeRedis()

	database.DB.DB.AutoMigrate(&user.User{})

	app := fiber.New()

	app.Use(logger.New(logger.Config{
		Format:     "[${time}] ${status} - ${latency} ${method} ${path}\n",
		TimeFormat: "2006-01-02 15:04:05",
		TimeZone:   "Europe/Belgrade",
	}))
	app.Use(cors.New())

	user.RegisterRoutes(app)

	app.Listen(":" + os.Getenv("APP_PORT"))
}
