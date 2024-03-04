package gofiber_session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/session/v2"
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
const STORED_COOKIE_NAME = "COOKIE_TRX_CUST_NUM"
const SESSION_DATE_ADDED = "SESSION_DATE_ADDED"
const APPID = "appid"

func (s *Session) GetTest() string {
	return s.Test
}

func SessionRequire(config Config) fiber.Handler {

	return func(ctx *fiber.Ctx) error {

		store := config.Session.Get(ctx)
		cookie := store.Get(STORED_COOKIE_NAME)
		if cookie == nil {
			log.Printf("SessionRequire-Middleware. Unable to find session for Cookie: %s ", STORED_COOKIE_NAME)
			ctx.SendStatus(http.StatusUnauthorized)
			return fmt.Errorf("Unauthorized access.")
			//SendStatus
		} else {
			log.Printf("SessionRequire-Middleware. Cookie: %s has been found. So far so good Cookie value:%s", STORED_COOKIE_NAME, cookie)
		}

		if err := ctx.Next(); err != nil {
			return err
		}

		return nil
	}

}

func ProxyAuthRequireV2(config Config) fiber.Handler {
	return func(ctx *fiber.Ctx) error {

		if config.WhiteRoutePrefixes != nil && len(config.WhiteRoutePrefixes) > 0 {
			for _, route := range config.WhiteRoutePrefixes {
				if strings.HasPrefix(ctx.Path(), route) {
					log.Printf("Open Route: %s, - ctx.Path(): %s", route, ctx.Path())
					return ctx.Next()
				}
			}
		}

		store := config.Session.Get(ctx)
		defer store.Save()

		if storeArr, err := json.Marshal(store); err != nil {
			log.Printf("Session %s", string(storeArr))
		}

		if config.InvalidateSessionPath != nil && len(*config.InvalidateSessionPath) > 0 && strings.HasPrefix(ctx.Path(), *config.InvalidateSessionPath) {
			log.Printf("InvalidateSessionPath: %s, - ctx.Path(): %s", *config.InvalidateSessionPath, ctx.Path())
			store.Set(SESSION_DATE_ADDED, "")
		}

		dateAdded := store.Get(SESSION_DATE_ADDED)
		if dateAdded != nil && isSessionActive(dateAdded.(string)) {
			setSessionTime(store)
			return ctx.Next()
		}

		log.Printf("*** ProxyAuthRequire-Middleware. Unable to find active session for ctx.Path(): %s", ctx.Path())

		q, err := url.ParseQuery(string(ctx.Request().URI().QueryString()))
		if err != nil {
			log.Printf(" ERROR parsing query: %v", err)
			ctx.Status(http.StatusBadRequest).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": "Invalid-Query-String", "message": "Invalid Access"})
			return fmt.Errorf("unauthorized Access")
		}
		if ctx != nil && ctx.Request() != nil && ctx.Request().URI() != nil && len(ctx.Request().URI().QueryString()) > 0 {
			log.Printf("Full Querystring before parse: %s", string(ctx.Request().URI().QueryString()))
		} else {
			log.Printf("Full Querystring before parse is empty")
		}
		//for key, values := range q {
		//	for _, value := range values {
		//		log.Printf("Parameter '%s' has value '%s'", key, value)
		//	}
		//}

		//Read URL Querystring
		onUrl := IdentityObj{}
		onUrl.AppId = q.Get(APPID)
		if len(strings.TrimSpace(onUrl.AppId)) == 0 {
			onUrl.AppId = store.Get(APPID).(string)
		}

		onUrl.TrxISAT = q.Get("TRX-ISAT")

		loginUrl := ""
		if len(strings.TrimSpace(onUrl.TrxISAT)) == 0 {

			log.Printf("Unable to find TRX-ISAT inside URL Query")
			if len(strings.TrimSpace(onUrl.AppId)) == 0 {
				log.Printf(" ERROR Unable to find appid inside URL Query")
				ctx.Status(http.StatusBadRequest).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": "Invalid-Query-String", "message": "Invalid Access"})
				return fmt.Errorf("unauthorized Access")
			}

			//Verify identity
			loginUrl = fmt.Sprintf("%s?appid=%s", config.LoginUrl, onUrl.AppId)

			log.Printf("Redirect to identity service: %s", loginUrl)
			return ctx.Redirect(loginUrl)
		}

		userSessionDetail, err := getUserDetails(config, onUrl.TrxISAT)
		if err != nil {
			log.Printf("Error user authentication: %v", err)
			ctx.Redirect(loginUrl)
		}

		userFunctions, err := fetchUserFunctionsByToken(config, onUrl.TrxISAT)
		if err != nil {
			ctx.Status(http.StatusInternalServerError).JSON(&fiber.Map{"status": http.StatusInternalServerError, "code": "Error-while-verifying-user-access", "message": "Error while verifying user access."})
			return fmt.Errorf("Error while verifying user access.")
		}

		if len(userFunctions) == 0 {
			ctx.Status(http.StatusUnauthorized).JSON(&fiber.Map{"status": http.StatusUnauthorized, "code": "Unauthorized-Access", "message": "Unauthorized Access"})
			return fmt.Errorf("Unauthorized Access")
		}

		store.Set(STORED_COOKIE_NAME, "fake-cookie-value")
		store.Set("AccountId", userSessionDetail.AccountId)
		store.Set("FirstName", userSessionDetail.FirstName)
		store.Set("LastName", userSessionDetail.LastName)
		store.Set("DefaultProfile", userSessionDetail.DefaultProfile)
		store.Set("UserId", userSessionDetail.UserId)
		store.Set(APPID, onUrl.AppId)
		store.Set("UserFunctions", userFunctions)
		setSessionTime(store)
		if err := ctx.Next(); err != nil {
			return err
		}

		return nil
	}
}

func fetchUserFunctionsByToken(config Config, token string) ([]UserFunctionItem, error) {

	log.Printf("Fetch user functions Token: %s", token)

	userFunctionBody := UserFunctionBody{token, config.Functions}
	userFunctionBodyJson, err := json.Marshal(userFunctionBody)

	log.Printf("Fetch user functions body: %s", string(userFunctionBodyJson))

	if config.FetchUserFunctionsUrl == nil {
		return nil, fmt.Errorf("FetchUserFunctionsUrl is required")
	}

	req, err := http.NewRequest(http.MethodPost, *config.FetchUserFunctionsUrl, bytes.NewBuffer(userFunctionBodyJson))
	if err != nil {
		log.Printf("Error while creating request for fetchUserFunctionsByToken", err)
		return nil, err
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error while fetching user functions", err)
		return nil, err
	}
	defer resp.Body.Close()

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		return nil, err
	}
	functionResponse := []UserFunctionItem{}
	err = json.NewDecoder(resp.Body).Decode(&functionResponse)
	if err != nil {
		log.Printf("Session Details resp error %v", err)
		return nil, err
	}

	return functionResponse, nil
}

type UserFunctionBody struct {
	Token               string   `json:"token"`
	RequestFunctionList []string `json:"functions"`
}
type UserFunctionItem struct {
	Id    string `json:"id"`
	Value string `json:"value"`
}

func getUserDetails(config Config, token string) (*SessionDetails, error) {

	//since we have trxISAT, we can verify the user
	log.Print("New Session, verify identity with IdentityService!")
	req, _ := http.NewRequest(http.MethodPost, config.CredentialUrl, bytes.NewBuffer([]byte(token)))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error user authentication: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("Identity Status Code %v", resp.StatusCode)
		return nil, err
	}

	//Read session details data from identity resp
	userSessionDetail := SessionDetails{}
	err = json.NewDecoder(resp.Body).Decode(&userSessionDetail)
	if err != nil {
		log.Printf("Session Details resp error %v", err)
		return nil, err
	}

	return &userSessionDetail, nil
}

func setSessionTime(store *session.Store) {
	currentTime := time.Now().Format(time.RFC3339)
	log.Printf("Saving Current Time for active session: %s", currentTime)
	store.Set(SESSION_DATE_ADDED, currentTime)
}

func isSessionActive(dateAddedStr string) bool {
	log.Printf("Checking if session is active %s", dateAddedStr)
	dateAddedTime, err := time.Parse(time.RFC3339, dateAddedStr)
	if err != nil {
		return false
	}

	if time.Now().Sub(dateAddedTime) > time.Hour {
		log.Printf("Session is older than 1 hour, redirecting to login")
		return false
	}
	return true
}

func ProxyAuthRequire(config Config, whiteRouteList []string) fiber.Handler {
	return func(ctx *fiber.Ctx) error {

		if whiteRouteList != nil && len(whiteRouteList) > 0 {
			for _, route := range whiteRouteList {
				log.Printf("Open Route: %s, - ctx.Path(): %s", route, ctx.Path())
				if route == ctx.Path() {
					return ctx.Next()
				}
			}
		}

		store := config.Session.Get(ctx)
		defer store.Save()

		log.Printf("*** ProxyAuthRequire-Middleware")

		q, err := url.ParseQuery(string(ctx.Request().URI().QueryString()))
		if err != nil {
			log.Printf(" ERROR parsing query: %v", err)
			ctx.Status(http.StatusBadRequest).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": "Invalid-Query-String", "message": "Invalid Access"})
			return fmt.Errorf("unauthorized Access")
		}

		//Read URL Querystring
		onUrl := IdentityObj{}
		onUrl.AppId = q.Get("appid")
		onUrl.TrxISAT = q.Get("TRX-ISAT")

		loginUrl := ""
		if len(strings.TrimSpace(onUrl.TrxISAT)) == 0 {

			log.Printf("Unable to find TRX-ISAT inside URL Query")
			if len(strings.TrimSpace(onUrl.AppId)) == 0 {
				log.Printf(" ERROR Unable to find appid inside URL Query")
				ctx.Status(http.StatusBadRequest).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": "Invalid-Query-String", "message": "Invalid Access"})
				return fmt.Errorf("unauthorized Access")
			}

			//Verify identity
			loginUrl = fmt.Sprintf("%s?appid=%s", config.LoginUrl, onUrl.AppId)

			log.Printf("Redirect to identity service: %s", loginUrl)
			return ctx.Redirect(loginUrl)
		}

		//since we have trxISAT, we can verify the user
		log.Print("New Session, verify identity with IdentityService!")
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

		store.Set(STORED_COOKIE_NAME, "fake-cookie-value")
		store.Set("AccountId", userSessionDetail.AccountId)
		store.Set("FirstName", userSessionDetail.FirstName)
		store.Set("LastName", userSessionDetail.LastName)
		store.Set("DefaultProfile", userSessionDetail.DefaultProfile)
		store.Set("UserId", userSessionDetail.UserId)
		store.Set("AppId", onUrl.AppId)
		if err := ctx.Next(); err != nil {
			return err
		}

		return nil
	}
}

func AuthRequire(config Config) fiber.Handler {
	return func(ctx *fiber.Ctx) error {

		cookieTk := ctx.Cookies(config.CookieName, INVALID_ACCESS)
		//Check cookie to authorize valid call's source
		if cookieTk == INVALID_ACCESS {
			ctx.Status(http.StatusUnauthorized).JSON(&fiber.Map{"status": http.StatusBadRequest, "code": http.StatusUnauthorized, "message": "Unauthorized Access"})
			return fmt.Errorf("Unauthorized Access")
		}

		log.Printf("****AuthRequire TRX_CUST_NUM: %s", cookieTk)

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

		////Check if already logged In and Update view if it is required
		//storedCookie := store.Get(STORED_COOKIE_NAME)
		//log.Printf("***AuthRequire %s: %s", STORED_COOKIE_NAME, storedCookie)
		//if storedCookie != nil && storedCookie != "" && storedCookie == cookieTk {
		//
		//	log.Printf("Already login")
		//	if len(onUrl.View) > 0 {
		//		store.Set("VIEW", onUrl.View)
		//	}
		//	return ctx.Next()
		//}

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
