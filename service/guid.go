package service

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"

	"github.com/google/uuid"
)

func CreateGuid() string {
	u, _ := uuid.NewUUID()
	return u.String()
}

func MakeUserHash(name, pass, key string) string {
	h := hmac.New(sha512.New, []byte(key))
	h.Write([]byte(name + pass))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func CheckUserHash(hash, name, pass, key string) bool {
	return MakeUserHash(name, pass, key) == hash
}
