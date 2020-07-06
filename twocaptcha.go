package twocaptcha

// package twocaptcha provides a Golang client for https://2captcha.com/

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ApiURL is the url of the 2captcha API endpoint
var ApiURL = "https://2captcha.com/in.php"

// ResultURL is the url of the 2captcha result API endpoint
var ResultURL = "https://2captcha.com/res.php"

// TwoCaptchaClient is an interface to https://2captcha.com/ API.
type TwoCaptchaClient struct {
	// ApiKey is the API key for the 2captcha.com API.
	// Valid key is required by all the functions of this library
	// See more details on https://2captcha.com/2captcha-api#solving_captchas
	ApiKey string
	// Client is a HTTP client for the api calls to 2captcha
	Client *http.Client
}

// New creates a TwoCaptchaClient instance
func New(apiKey string) *TwoCaptchaClient {
	return &TwoCaptchaClient{
		ApiKey: apiKey,
		Client: http.DefaultClient,
	}
}

// SolveCaptcha performs a normal captcha solving request to 2captcha.com
// and returns with the solved captcha if the request was successful.
// Valid ApiKey is required.
// See more details on https://2captcha.com/2captcha-api#solving_normal_captcha
func (c *TwoCaptchaClient) SolveCaptcha(url string) (string, error) {

	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != 200 {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	strBase64 := base64.StdEncoding.EncodeToString(body)

	captchaId, err := c.apiRequest(
		ApiURL,
		map[string]string{
			"method":   "base64",
			"body":     strBase64,
			"phrase":   "1",
			"regsense": "1",
		},
		0,
		3,
	)

	if err != nil {
		return "", err
	}

	return c.apiRequest(
		ResultURL,
		map[string]string{
			"id":     captchaId,
			"action": "get",
		},
		5,
		20,
	)
}

// SolveRecaptchaV2 performs a recaptcha v2 solving request to 2captcha.com
// and returns with the solved captcha if the request was successful.
// Valid ApiKey is required.
// See more details on https://2captcha.com/2captcha-api#solving_recaptchav2_new
func (c *TwoCaptchaClient) SolveRecaptchaV2(siteURL, recaptchaKey string) (string, error) {
	captchaId, err := c.apiRequest(
		ApiURL,
		map[string]string{
			"googlekey": recaptchaKey,
			"pageurl":   siteURL,
			"method":    "userrecaptcha",
		},
		0,
		3,
	)

	if err != nil {
		return "", err
	}

	return c.apiRequest(
		ResultURL,
		map[string]string{
			"googlekey": recaptchaKey,
			"pageurl":   siteURL,
			"method":    "userrecaptcha",
			"id":        captchaId,
			"action":    "get",
		},
		5,
		20,
	)
}

func (c *TwoCaptchaClient) apiRequest(URL string, params map[string]string, delay time.Duration, retries int) (string, error) {
	if retries <= 0 {
		return "", errors.New("Maximum retries exceeded")
	}
	time.Sleep(delay * time.Second)
	form := url.Values{}
	form.Add("key", c.ApiKey)
	for k, v := range params {
		form.Add(k, v)
	}

	req, err := http.NewRequest("POST", URL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	if strings.Contains(string(body), "CAPCHA_NOT_READY") {
		return c.apiRequest(URL, params, delay, retries-1)
	}
	if !strings.Contains(string(body), "OK|") {
		return "", errors.New("Invalid respponse from 2captcha: " + string(body))
	}
	return string(body[3:]), nil
}
