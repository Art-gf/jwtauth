package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"time"
)

type Payload struct {
	UserId  string `json:"userId"`
	ExpTime string `json:"exp"`
}

// Create new JWT with HMAC
func CreateJwtHmacString(alg string, payload Payload, key string) (string, error) {
	var funcHash func() hash.Hash
	switch alg {
	case "HS512":
		funcHash = sha512.New
	default:
		funcHash = sha256.New
		alg = "HS256"
	}
	signatureToken := hmac.New(funcHash, []byte(key))

	headerJson := []byte(`{"typ":"JWT","alg":"` + alg + `"}`)

	payload.ExpTime = fmt.Sprint(time.Now().Add(time.Minute * 15).Unix())
	payloadJson, _ := json.Marshal(payload)

	headerToken := base64.RawURLEncoding.EncodeToString(headerJson)
	payloadToken := base64.RawURLEncoding.EncodeToString(payloadJson)
	unsignedToken := headerToken + "." + payloadToken
	signatureToken.Write([]byte(unsignedToken))
	return unsignedToken + "." + base64.RawURLEncoding.EncodeToString(signatureToken.Sum(nil)), nil
}

// func prepData() {

// }
