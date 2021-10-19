package service

// Token engine

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
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

func (c *RefreshToken) ReturnString() string {
	return c.RefreshPayload.ReturnString() + "." + c.AccessSignature + "." + c.RefreshSignature
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

func GenAccessToken(pT TokenPayload, key string) (c AccessToken) {
	c.AccessHeader = TokenHeader{Type: "JWT", Alg: "HS512"}
	c.AccessPayload = pT
	c.AccessSignature = GenSignature(c.AccessHeader.ReturnString()+"."+pT.ReturnString(), key)
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

func CheckAccessToken(t string, key string) (pl TokenPayload, exp bool, err error) {
	userToken := AccessToken{}
	s, err := SplitToken(t)
	if err != nil {
		return
	}
	if s[2] != GenSignature(s[0]+"."+s[1], key) {
		err = errors.New("unvalid access token ")
		return
	}
	if DecodeString(s[1], &userToken.AccessPayload) != nil {
		err = errors.New("payload access reading error")
		return
	}
	pl = userToken.AccessPayload
	if userToken.AccessPayload.ExpTime <= time.Now().Unix() {
		return
	}
	exp = true
	return
}

func CheckRefreshToken(tA, tR string, key string) (pl TokenPayload, exp bool, err error) {
	userToken := RefreshToken{}
	sA, err := SplitToken(tA)
	if err != nil {
		return
	}
	sR, err := SplitToken(tR)
	if err != nil {
		return
	}
	if DecodeString(sR[0], &userToken.RefreshPayload) != nil {
		err = errors.New("payload refresh reading error")
		return
	}
	if sA[2] != sR[1] {
		err = errors.New("unvalid refresh token")
		return
	}
	if sR[2] != GenSignature(userToken.RefreshPayload.ReturnString()+"."+sA[2], key) {
		err = errors.New("unvalid refresh token")
		return
	}
	pl = userToken.RefreshPayload
	if userToken.RefreshPayload.ExpTime <= time.Now().Unix() {
		return
	}
	exp = true
	return
}

func BcryptHash(data string) string {
	bh, err := bcrypt.GenerateFromPassword([]byte(data), bcrypt.DefaultCost)
	if err != nil {
		return "error"
	}
	return string(bh)
}

func BcryptCompare(data, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(data)) == nil
}

func PayloadMinute(m int) int64 {
	return time.Now().Add(time.Minute * time.Duration(m)).Unix()
}
