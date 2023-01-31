package main

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/session/v2"
	gofiber_session "github.com/transactrx/trx-gofiber-session/pkg/gofiber-session"
	"log"
	"time"
)

func main() {

	store := session.New(session.Config{Expiration: time.Minute * 1})

	config, err := gofiber_session.CreateConfig("https://login.transactrx.com", "https://login.transactrx.com/credential", store, "validAuthCookieName", false)
	if err != nil {
		log.Printf("Error creating config: %v", err)
	}

	app := fiber.New()
	app.Use(gofiber_session.AuthRequire(config))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, World!")
	})

	app.Listen(":3000")

}
