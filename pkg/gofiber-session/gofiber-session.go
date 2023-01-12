package gofiber_session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type Session struct {
	Test string
}

func (s *Session) GetTest() string {
	return s.Test
}

func AuthRequire(c *fiber.Ctx, config Config) fiber.Handler {
	return func(ctx *fiber.Ctx) error {

		store := config.Session.Get(ctx)

		if store.Get("TrxIsat") != nil && store.Get("TrxIsat") != "" {
			//already login
			log.Printf("Already login")
			return ctx.Next()
		}

		log.Print("New Session, verify identity with IdentityService!")

		onUrl := IdentityObj{}

		q, err := url.ParseQuery(string(c.Request().URI().QueryString()))
		if err != nil {
			log.Printf(" ERROR parsing query: %v", err)
		}

		onUrl.AppId = q.Get("appid")
		onUrl.Mode = q.Get("mode")
		onUrl.TrxISAT = q.Get("TRX-ISAT")
		onUrl.View = q.Get("view")
		onUrl.SSCOMMON = q.Get("SSCOMMON")
		onUrl.ProfileName = q.Get("PROFILENAME")

		loginUrl := fmt.Sprintf("%s?appid=%s&SSCOMMON=%s&view=%s", config.LoginUrl, onUrl.AppId, onUrl.SSCOMMON, onUrl.View)

		if len(strings.TrimSpace(onUrl.TrxISAT)) == 0 {
			return c.Redirect(loginUrl)
		}

		req, _ := http.NewRequest(http.MethodPost, config.CredentialUrl, bytes.NewBuffer([]byte(onUrl.TrxISAT)))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf(" PANIC client do %v", err.Error())
			return c.Redirect(loginUrl)
		}
		defer resp.Body.Close()

		userSessionDetail := SessionDetails{}
		err = json.NewDecoder(resp.Body).Decode(&userSessionDetail)
		if err != nil {
			log.Printf(" PANIC SessionDetails resp error %v", err)
			return c.Redirect(loginUrl)
		}

		log.Printf(" Resp.StatusCode %v", resp.StatusCode)
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			log.Printf(" PANIC PREPARE TO REDIRECT resp.StatusCode %v", resp.StatusCode)
			return c.Redirect(loginUrl)
		}

		userSessionDetail.AppView = onUrl.View

		defer store.Save()

		store.Set("VIEW", onUrl.View)
		//sess.Set("USER_SESSION_DETAIL", userSessionDetail)
		store.Set("AccountId", userSessionDetail.AccountId)
		store.Set("FirstName", userSessionDetail.FirstName)
		store.Set("LastName", userSessionDetail.LastName)
		store.Set("DefaultProfile", userSessionDetail.DefaultProfile)
		store.Set("AppView", userSessionDetail.AppView)
		store.Set("TrxIsat", userSessionDetail.TrxIsat)
		store.Set("UserId", userSessionDetail.UserId)

		if err := ctx.Next(); err != nil {
			return err
		}

		return nil
	}
}
