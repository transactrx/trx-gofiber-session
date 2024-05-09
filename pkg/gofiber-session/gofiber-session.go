package gofiber_session

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/session/v2"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type Session struct {
	Test string
}

const INVALID_ACCESS = "INVALID-ACCESS"
const STORED_COOKIE_NAME = "COOKIE_TRX_CUST_NUM"
const TRX_USER_DETAILS = "TRX_USER_DETAILS"
const TRX_VIEW = "TRX_VIEW"
const VIEW = "VIEW"

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

var openResourceRegexp *regexp.Regexp

func AuthorizationProxyCheck(session *session.Session) fiber.Handler {
	combinedOpenResourcePatterns := ".*/gxt/.*|.*nocache.*|.*\\.cache\\..*|.*\\/bootstrap\\.min\\..*|angular\\.min\\.js|.*\\/zapatec\\/.*\\..*|.*\\/pdfjs\\/.*\\.js(?:\\?.*)?$|.*\\.(jpg|jpeg|png|gif|svg)(?:\\?.*)?$|.*\\.css(?:\\?.*)?$" // .*\.js(?:\?.*)?$

	if len(combinedOpenResourcePatterns) > 0 {
		var err error
		if openResourceRegexp, err = regexp.Compile(combinedOpenResourcePatterns); err != nil {
			log.Panicf("Error compiling openResourceRegexp: %v", err)
		}
	}
	return func(ctx *fiber.Ctx) error {
		//log.Println("-------------------------------------------")
		//log.Printf("-> AuthorizationFilter -  %s", ctx.OriginalURL())

		if websocket.IsWebSocketUpgrade(ctx) {
			return ctx.Next()
		}

		q, err := url.ParseQuery(string(ctx.Request().URI().QueryString()))
		if err != nil {
			log.Printf(" ERROR parsing query: %v", err)
			ctx.Status(http.StatusUnauthorized).JSON(&fiber.Map{"status": http.StatusUnauthorized, "code": "Unauthorized-Access", "message": "Unauthorized Access"})
			return fmt.Errorf("Unauthorized Access")
		}

		path := ctx.Path()
		//CHECK IF URL MATCHES THE OPEN RESOURCE REGEXP. ALLOW ACCESS BECAUSE THESE RESOURCES ARE AUTHORIZED TO BE OPENED DUE TO THEY MUSTILY CAME FROM CLOUDFRONT WITHOUT SESSION
		if openResourceRegexp != nil && openResourceRegexp.MatchString(path) {
			log.Printf("Resource Match to Opened Pattern: %s", ctx.OriginalURL())
			return ctx.Next()
		}

		store := session.Get(ctx)
		saveStoreRequired := false

		//VIEW
		viewStore := getFromStore(VIEW, store)
		viewHeader := getFromHeader(TRX_VIEW, ctx)
		if viewHeader != nil && len(*viewHeader) > 0 && (viewStore == nil || len(*viewStore) == 0 || *viewStore != *viewHeader) {
			store.Set("VIEW", viewHeader)
			saveStoreRequired = true
		} else {
			viewQuery := q.Get("view")
			if viewQuery != "" && (viewStore == nil || len(*viewStore) == 0 || *viewStore != viewQuery) {
				store.Set(VIEW, viewQuery)
				saveStoreRequired = true
			}
		}

		userDetailsStoreStr := getFromStore(TRX_USER_DETAILS, store)
		userDetailsHeaderStr := getFromHeader(TRX_USER_DETAILS, ctx)

		//if userDetailsStoreStr != nil && len(*userDetailsStoreStr) > 0 {
		//	log.Printf("User Details Store has value.", *userDetailsStoreStr)
		//}

		if (userDetailsStoreStr == nil || len(*userDetailsStoreStr) == 0) && (userDetailsHeaderStr == nil || len(*userDetailsHeaderStr) == 0) {
			ctx.Status(http.StatusUnauthorized).JSON(&fiber.Map{"status": http.StatusUnauthorized, "code": "Unauthorized-Access", "message": "Unauthorized Access"})
			return fmt.Errorf("unauthorized Access")
		}

		if userDetailsHeaderStr == nil || len(*userDetailsHeaderStr) == 0 {
			//log.Print("user Details Header is empty and will continue use from store, then next() ")
			return ctx.Next()
		}

		if userDetailsStoreStr == nil || *userDetailsHeaderStr != *userDetailsStoreStr {
			//log.Print("user Details Header !=  user Details Store, then update it on store")
			toStore := *userDetailsHeaderStr
			store.Set(TRX_USER_DETAILS, toStore)
			saveStoreRequired = true
		}

		if saveStoreRequired {
			store.Save()
		}
		return ctx.Next()
	}
}

func getFromStore(key string, store *session.Store) *string {

	viewStoredInt := store.Get(key)
	if viewStoredInt != nil && len(viewStoredInt.(string)) > 0 {
		value := viewStoredInt.(string)
		return &value
	}
	return nil
}

func getFromHeader(key string, ctx *fiber.Ctx) *string {
	viewHeaderBA := ctx.Request().Header.Peek(key)
	if viewHeaderBA != nil && len(viewHeaderBA) > 0 {
		value := string(viewHeaderBA)
		return &value
	}
	return nil
}

func ConnectionLimiter(maxConnectCount int, expiration time.Duration, skip func(c *fiber.Ctx) bool) fiber.Handler {
	limiterConfig := limiter.Config{
		Max:        maxConnectCount, // 5
		Expiration: expiration,      // 5 * time.Second, // expiration time of the limit
		Next:       skip,
	}

	return limiter.New(limiterConfig)
}
