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

func AuthRequire(config Config) fiber.Handler {
	return func(ctx *fiber.Ctx) error {

		const INVALID_ACCESS = "INVALID-ACCESS"
		//Check Authorize Call's Source Cookies
		log.Printf("comming config.cookieName: %s, cookie value: %s", config.cookieName, ctx.Cookies(config.cookieName, INVALID_ACCESS))
		if ctx.Cookies(config.cookieName, INVALID_ACCESS) == INVALID_ACCESS {
			//ctx.Redirect(config.LoginUrl)
			ctx.Status(http.StatusUnauthorized).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": http.StatusUnauthorized, "message": "Unauthorize Access"})
			return fmt.Errorf("Unauthorize Access")
		}

		store := config.Session.Get(ctx)

		onUrl := IdentityObj{}

		q, err := url.ParseQuery(string(ctx.Request().URI().QueryString()))
		if err != nil {
			log.Printf(" ERROR parsing query: %v", err)
			ctx.Status(http.StatusBadRequest).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": "Invalid-Query-String", "message": "Invalid Access"})
			return fmt.Errorf("Unauthorize Access")
		}

		//Read URL querystrig
		onUrl.AppId = q.Get("appid")
		onUrl.Mode = q.Get("mode")
		onUrl.TrxISAT = q.Get("TRX-ISAT")
		onUrl.View = q.Get("view")
		onUrl.SSCOMMON = q.Get("SSCOMMON")
		onUrl.ProfileName = q.Get("PROFILENAME")

		defer store.Save()

		//Check if already logged In and Update view if it is required
		if store.Get("TrxIsat") != nil && store.Get("TrxIsat") != "" {
			log.Printf("session TrxIsat: %s", store.Get("TrxIsat"))
			log.Printf("Already login")
			if len(onUrl.View) > 0 {
				store.Set("VIEW", onUrl.View)
			}
			return ctx.Next()
		}

		log.Print("New Session, verify identity with IdentityService!")

		//Verify identity
		loginUrl := fmt.Sprintf("%s?appid=%s&SSCOMMON=%s&view=%s&PROFILENAME=%s&mode=%s", config.LoginUrl, onUrl.AppId, onUrl.SSCOMMON, onUrl.View, onUrl.ProfileName, onUrl.Mode)

		if len(strings.TrimSpace(onUrl.TrxISAT)) == 0 {
			log.Printf("Redirect loginUrl: %s", loginUrl)
			return ctx.Redirect(loginUrl)
		}

		req, _ := http.NewRequest(http.MethodPost, config.CredentialUrl, bytes.NewBuffer([]byte(onUrl.TrxISAT)))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Error user authentication: %v", err)
			return ctx.Redirect(loginUrl)
		}
		defer resp.Body.Close()

		//read session details data from identity
		userSessionDetail := SessionDetails{}
		err = json.NewDecoder(resp.Body).Decode(&userSessionDetail)
		if err != nil {
			log.Printf("Session Details resp error %v", err)
			return ctx.Redirect(loginUrl)
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			log.Printf(" PANIC PREPARE TO REDIRECT resp.StatusCode %v", resp.StatusCode)
			return ctx.Redirect(loginUrl)
		}

		//Save session
		if len(onUrl.View) > 0 {
			userSessionDetail.AppView = onUrl.View
			store.Set("VIEW", onUrl.View)
			store.Set("AppView", userSessionDetail.AppView)
		}

		store.Set("AccountId", userSessionDetail.AccountId)
		store.Set("FirstName", userSessionDetail.FirstName)
		store.Set("LastName", userSessionDetail.LastName)
		store.Set("DefaultProfile", userSessionDetail.DefaultProfile)

		store.Set("TrxIsat", userSessionDetail.TrxIsat)
		store.Set("UserId", userSessionDetail.UserId)

		if err := ctx.Next(); err != nil {
			return err
		}

		return nil
	}
}
