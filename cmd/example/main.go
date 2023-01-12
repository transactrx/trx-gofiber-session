package main

import (
	"fmt"
	gofiber_session "github.com/transactrx/trx-gofiber-session/pkg/gofiber-session"
)

func main() {
	sess := gofiber_session.Session{Test: "hello world!"}

	fmt.Println(sess.GetTest())
}
