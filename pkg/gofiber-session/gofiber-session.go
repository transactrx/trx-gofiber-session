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
	"time"
)

type Session struct {
	Test string
}

const INVALID_ACCESS = "INVALID-ACCESS"
const STORED_TRX_COOKIE_NAME = "COOKIE_TRX_CUST_NUM"
const USER_COOKIE_NAME = "COOKIE_USER_NAME"

func (s *Session) GetTest() string {
	return s.Test
}

func SessionRequire(config Config) fiber.Handler {

	return func(ctx *fiber.Ctx) error {

		store := config.Session.Get(ctx)
		sessionTrxCookieValue := store.Get(STORED_TRX_COOKIE_NAME)
		if sessionTrxCookieValue == nil {
			log.Printf("SessionRequire-Middleware. Unable to find session for Cookie: %s ", STORED_TRX_COOKIE_NAME)
			ctx.SendStatus(http.StatusUnauthorized)
			return fmt.Errorf("Unauthorized access.")
			//SendStatus
		} else {
			log.Printf("SessionRequire-Middleware. Cookie: %s has been found. So far so good Cookie value:%s", STORED_TRX_COOKIE_NAME, sessionTrxCookieValue)
		}

		if err := ctx.Next(); err != nil {
			return err
		}

		return nil
	}

}

func AuthRequire(config Config) fiber.Handler {
	return func(ctx *fiber.Ctx) error {

		trxCookie := ctx.Cookies(config.CookieName, INVALID_ACCESS)
		//Check cookie to authorize valid call's source
		if trxCookie == INVALID_ACCESS {
			ctx.Status(http.StatusUnauthorized).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": http.StatusUnauthorized, "message": "Unauthorized Access"})
			return fmt.Errorf("Unauthorized Access")
		}

		log.Printf("****AuthRequire TRX_CUST_NUM: %s", trxCookie)

		userCookie := ctx.Cookies(USER_COOKIE_NAME, INVALID_ACCESS)
		if userCookie == INVALID_ACCESS {
			log.Print("****USER COOKIE DO NOT EXISTS")
		} else {
			log.Printf("****USER COOKIE DO NOT EXISTS: %s", userCookie)
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
		sessionTrxCookieValue := store.Get(STORED_TRX_COOKIE_NAME)
		sessionUserCookieValue := store.Get(USER_COOKIE_NAME)
		log.Printf("***AuthRequire %s: %s", STORED_TRX_COOKIE_NAME, sessionTrxCookieValue)
		if sessionTrxCookieValue != nil && len(strings.TrimSpace(sessionTrxCookieValue.(string))) > 0 && sessionTrxCookieValue.(string) == trxCookie && sessionUserCookieValue != nil && len(strings.TrimSpace(sessionUserCookieValue.(string))) > 0 && sessionUserCookieValue.(string) == userCookie {

			log.Printf("Already login")
			if len(onUrl.View) > 0 {
				store.Set("VIEW", onUrl.View)
			}
			return ctx.Next()
		} else {
			log.Printf("sessionTrxCookieValue: %v, trxCookie: %v, sessionUserCookieValue: %v, userCookie: %v", sessionTrxCookieValue, trxCookie, sessionUserCookieValue, userCookie)
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

		// create and save USER_COOKIE_NAME cookie with userSessionDetail.UserId value
		cookie := createCookie(USER_COOKIE_NAME, userSessionDetail.UserId, "/", -1)
		ctx.Cookie(cookie)

		//Save session
		if len(onUrl.View) > 0 {
			userSessionDetail.AppView = onUrl.View
			store.Set("VIEW", onUrl.View)
			store.Set("AppView", userSessionDetail.AppView)
		}
		store.Set(STORED_TRX_COOKIE_NAME, trxCookie)
		store.Set(USER_COOKIE_NAME, userSessionDetail.UserId)
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

func createCookie(name string, value string, path string, maxAge int) *fiber.Cookie {
	cookie := new(fiber.Cookie)

	cookie.Name = name
	cookie.Value = url.QueryEscape(value)
	cookie.Path = path
	cookie.MaxAge = maxAge
	cookie.Secure = true
	cookie.HTTPOnly = true
	cookie.Expires = time.Now().Add(24 * time.Hour)

	return cookie
}
