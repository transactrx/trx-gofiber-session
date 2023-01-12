package gofiber_session

type Config struct {
	MemcachedServerList []string
	MemcachedSeed       string
	MaxIdleConns        int
	LoginUrl            string
	CredentialUrl       string
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
