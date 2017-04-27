package edgegrid

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/satori/go.uuid"
	"gopkg.in/ini.v1"
)

const (
	moniker string = "EG1-HMAC-SHA256"
)

// EdgeGrid Api interface to Akamai
type EdgeGrid struct {
	host         string
	clientToken  string
	clientSecret string
	accessToken  string
	maxBody      string
}

// New returns a new instance of Edgecast
func New(host, clientToken, clientSecret, accessToken, maxBody string) *EdgeGrid {

	e := new(EdgeGrid)

	e.host = host
	e.clientToken = clientToken
	e.clientSecret = clientSecret
	e.accessToken = accessToken
	e.maxBody = maxBody

	return e
}

// NewFromIni returns a new instance of Edgecast
func NewFromIni(iniFile string) *EdgeGrid {

	cfg, err := ini.Load(iniFile)
	if err != nil {
		panic(err)
	}

	section, err := cfg.GetSection("default")
	if err != nil {
		panic(err)
	}

	host, err := section.GetKey("host")
	if err != nil {
		panic("Host name not found in config file")
	}

	clientToken, err := section.GetKey("client_token")
	if err != nil {
		panic("Client Token not found in config file")
	}

	clientSecret, err := section.GetKey("client_secret")
	if err != nil {
		panic("Client Secret not found in config file")
	}

	accessToken, err := section.GetKey("access_token")
	if err != nil {
		panic("Acces Token not found in config file")
	}

	maxBody, err := section.GetKey("max_body")
	if err != nil {
		panic("Max Body not found in config file")
	}

	return New(host.String(), clientToken.String(), clientSecret.String(), accessToken.String(), maxBody.String())
}

// Send a api request to Akamai
func (e *EdgeGrid) Send(method, path, body string) (*http.Response, error) {
	client := &http.Client{}
	method = strings.ToUpper(method)

	if method == "POST" && (string(body) == "{}" || string(body) == "") {
		return nil, errors.New("found empty data set")
	}

	r, _ := http.NewRequest(method, e.host+path, bytes.NewBufferString(body))
	r.Header.Add("Content-Type", "application/json")
	r.Header.Add("Authorization", e.signedRequest(method, path, r.Header, body))
	return client.Do(r)
}

func (e *EdgeGrid) signedRequest(method, path string, headers http.Header, body string) string {

	t := time.Now().UTC()
	timestamp := t.Format("20060102T15:04:05-0700")

	joinedPairs := []string{
		"client_token=" + e.clientToken,
		"access_token=" + e.accessToken,
		"timestamp=" + timestamp,
		"nonce=" + uuid.NewV4().String(),
	}

	authHeader := moniker + " " + strings.Join(joinedPairs, ";")
	signingKey := ComputeHmac256(timestamp, e.clientSecret)
	authHeader += ";signature=" + ComputeHmac256(dataToSign(method, e.host+path, authHeader, headers, body), signingKey)

	return authHeader
}

func dataToSign(method, requestURL string, authHeader string, headers http.Header, body string) string {

	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return ""
	}

	bodyHash := ""
	if method == "POST" && len(body) > 0 {
		bodyHash = Compute256(body)
	}

	dataToSign := []string{
		method,
		parsedURL.Scheme,
		parsedURL.Host,
		parsedURL.Path + parsedURL.RawQuery,
		"",
		bodyHash,
		authHeader,
	}

	var returnString string
	for _, k := range dataToSign {
		returnString += k + "\t"
	}

	return strings.TrimSpace(returnString) + ";"
}
