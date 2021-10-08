package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"hash"
	"time"
)

type Payload struct {
	UserId  string `json:"userId"`
	TokenId string `json:"tokenId"`
	ExpTime int64  `json:"tokenExp"`
}

type Token struct {
	Token   string
	TokenId string
	ExpTime int64
}

type DoubleToken struct {
	AccessToken  Token
	RefreshToken Token
}

// Create new JWT with HMAC
func GenToken(alg string, payload Payload, key string) *Token {
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

	payload.ExpTime = time.Now().Unix() + payload.ExpTime
	payloadJson, _ := json.Marshal(payload)

	headerToken := base64.RawURLEncoding.EncodeToString(headerJson)
	payloadToken := base64.RawURLEncoding.EncodeToString(payloadJson)
	unsignedToken := headerToken + "." + payloadToken
	signatureToken.Write([]byte(unsignedToken))
	return &Token{Token: unsignedToken + "." + base64.RawURLEncoding.EncodeToString(signatureToken.Sum(nil)),
		TokenId: payload.TokenId,
		ExpTime: payload.ExpTime}
}

func GenDoubleToken(aAlg, rAlg string, aPayload, rPayload Payload, aKey, rKey string) *DoubleToken {
	return &DoubleToken{AccessToken: *GenToken(aAlg, aPayload, aKey), RefreshToken: *GenToken(rAlg, rPayload, rKey)}
}
