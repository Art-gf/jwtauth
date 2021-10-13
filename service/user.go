package service

// User engine. User created with type bson for mongodb using

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"

	"github.com/google/uuid"
)

type User struct {
	Login       string `bson:"login,omitempty"`
	Guid        string `bson:"guid,omitempty"`
	UserHash    string `bson:"userhash,omitempty"`
	RefreshHash string `bson:"refhash,omitempty"`
}

func NewUser(login, pass, key string) User {
	return User{
		Login:       login,
		Guid:        CreateGuid(),
		UserHash:    MakeUserHash(login, pass, key),
		RefreshHash: "empty",
	}
}

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
