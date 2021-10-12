package service

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type TokenHeader struct {
	Type string `json:"typ"`
	Alg  string `json:"alg"`
}

type TokenPayload struct {
	Guid    string `json:"guid"`
	ExpTime int64  `json:"exp"`
}

type AccessToken struct {
	AccessHeader    TokenHeader  `json:"header"`
	AccessPayload   TokenPayload `json:"payload"`
	AccessSignature string       `json:"signature"`
}

type RefreshToken struct {
	RefreshPayload   TokenPayload
	AccessSignature  string
	RefreshSignature string
}

func (c *AccessToken) ReturnString() string {
	return c.AccessHeader.ReturnString() + "." + c.AccessPayload.ReturnString() + "." + c.AccessSignature
}

func (h *TokenHeader) ReturnString() string {
	hJ, _ := json.Marshal(h)
	return base64.RawURLEncoding.EncodeToString(hJ)
}

func (p *TokenPayload) ReturnString() string {
	pJ, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(pJ)
}

func GenSignature(data, key string) string {
	h := hmac.New(sha512.New, []byte(key))
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func GenAccessToken(hT TokenHeader, pT TokenPayload, key string) (c AccessToken) {
	c.AccessSignature = GenSignature(hT.ReturnString()+"."+pT.ReturnString(), key)
	return
}

func (a *AccessToken) GenRefreshToken(p TokenPayload, key string) (r RefreshToken) {
	r.RefreshPayload = p
	r.AccessSignature = a.AccessSignature
	r.RefreshSignature = GenSignature(r.RefreshPayload.ReturnString()+"."+r.AccessSignature, key)
	return
}

func DecodeString(data string, i interface{}) error {
	raw, err := base64.RawStdEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, i); err != nil {
		return err
	}
	return nil
}

func SplitToken(token string) (s []string, err error) {
	s = strings.Split(token, ".")
	if len(s) != 3 {
		return nil, errors.New("unsupported token structure")
	} else {
		return s, nil
	}
}

func CheckAccessToken(s []string, key string) (b bool, err error) {
	userToken := AccessToken{}

	if DecodeString(s[0], &userToken.AccessHeader) != nil {
		return false, errors.New("header access reading error")
	}

	if DecodeString(s[1], &userToken.AccessPayload) != nil {
		return false, errors.New("payload access reading error")
	}

	if s[2] != GenSignature(userToken.AccessHeader.ReturnString()+"."+userToken.AccessPayload.ReturnString(), key) {
		return false, errors.New("unvalid access token")
	}

	if userToken.AccessPayload.ExpTime <= time.Now().Unix() {
		return false, nil
	}

	return true, nil
}

func CheckRefreshToken(sA, sR []string, key string) (b bool, err error) {
	userToken := RefreshToken{}
	if DecodeString(sR[0], &userToken.RefreshPayload) != nil {
		return false, errors.New("payload refresh reading error")
	}

	if sA[2] != sR[1] {
		return false, errors.New("unvalid refresh token")
	}

	if sR[2] != GenSignature(userToken.RefreshPayload.ReturnString()+"."+sA[2], key) {
		return false, errors.New("unvalid refresh token")
	}

	if userToken.RefreshPayload.ExpTime <= time.Now().Unix() {
		return false, nil
	}

	return true, nil
}
