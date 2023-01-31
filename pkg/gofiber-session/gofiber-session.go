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
		const STORED_COOKIE_NAME = "COOKIE_TK"

		cookieTk := ctx.Cookies(config.cookieName, INVALID_ACCESS)
		//Check cookie to authorize valid call's source
		if cookieTk == INVALID_ACCESS {
			ctx.Status(http.StatusUnauthorized).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": http.StatusUnauthorized, "message": "Unauthorized Access"})
			return fmt.Errorf("Unauthorized Access")
		}

		store := config.Session.Get(ctx)
		defer store.Save()

		onUrl := IdentityObj{}

		q, err := url.ParseQuery(string(ctx.Request().URI().QueryString()))
		if err != nil {
			log.Printf(" ERROR parsing query: %v", err)
			ctx.Status(http.StatusBadRequest).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": "Invalid-Query-String", "message": "Invalid Access"})
			return fmt.Errorf("Unauthorized Access")
		}

		//Read URL Querystring
		onUrl.AppId = q.Get("appid")
		onUrl.Mode = q.Get("mode")
		onUrl.TrxISAT = q.Get("TRX-ISAT")
		onUrl.View = q.Get("view")
		onUrl.SSCOMMON = q.Get("SSCOMMON")
		onUrl.ProfileName = q.Get("PROFILENAME")

		//Check if already logged In and Update view if it is required
		log.Printf("config.mandatoryAuth : %s", config.mandatoryAuth)
		storedCookie := store.Get(STORED_COOKIE_NAME)
		if storedCookie != nil && storedCookie != "" && storedCookie == cookieTk && (config.mandatoryAuth == nil || *config.mandatoryAuth != true) {

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

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			log.Printf("Identity Status Code %v", resp.StatusCode)
			return ctx.Redirect(loginUrl)
		}

		//Read session details data from identity resp
		userSessionDetail := SessionDetails{}
		err = json.NewDecoder(resp.Body).Decode(&userSessionDetail)
		if err != nil {
			log.Printf("Session Details resp error %v", err)
			return ctx.Redirect(loginUrl)
		}

		//Save session
		if len(onUrl.View) > 0 {
			userSessionDetail.AppView = onUrl.View
			store.Set("VIEW", onUrl.View)
			store.Set("AppView", userSessionDetail.AppView)
		}
		store.Set(STORED_COOKIE_NAME, cookieTk)
		store.Set("AccountId", userSessionDetail.AccountId)
		store.Set("FirstName", userSessionDetail.FirstName)
		store.Set("LastName", userSessionDetail.LastName)
		store.Set("DefaultProfile", userSessionDetail.DefaultProfile)
		store.Set("UserId", userSessionDetail.UserId)

		if err := ctx.Next(); err != nil {
			return err
		}

		return nil
	}
}
