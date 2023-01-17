package gofiber_session

import (
	"fmt"
	"github.com/gofiber/session/v2"
	"strings"
)

type Config struct {
	LoginUrl      string
	CredentialUrl string
	Session       *session.Session
	cookieName    string
}

type IdentityObj struct {
	AppId       string `json:"appid"`
	TrxISAT     string `json:"TRX-ISAT"`
	View        string `json:"view"`
	Mode        string `json:"mode"`
	SSCOMMON    string `json:"SSCOMMON"`
	ProfileName string `json:"PROFILENAME"`
	File        string `json:"file"`
	ReportId    string `json:"reportId"`
}

type SessionDetails struct {
	AccountId      string `json:"accountId"`
	UserId         string `json:"userId"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	DefaultProfile string `json:"defaultProfile"`
	AppView        string `json:"appView"`
	TrxIsat        string `json:"trxIsat"`
}

func CreateConfig(loginUrl string, credentialUrl string, session *session.Session, cookieName string) (Config, error) {

	if len(strings.TrimSpace(loginUrl)) == 0 {
		return Config{}, fmt.Errorf("loginUrl is required")
	}
	if len(strings.TrimSpace(credentialUrl)) == 0 {
		return Config{}, fmt.Errorf("credentialUrl is required")
	}
	if session == nil {
		return Config{}, fmt.Errorf("session is required")
	}

	if len(strings.TrimSpace(cookieName)) == 0 {
		return Config{}, fmt.Errorf("cookieName is required")
	}

	return Config{
		LoginUrl:      loginUrl,
		CredentialUrl: credentialUrl,
		Session:       session,
		cookieName:    cookieName,
	}, nil
}
