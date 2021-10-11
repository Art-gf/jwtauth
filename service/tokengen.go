package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"strings"
	"time"
)

type Header struct {
	Type string `json:"typ"`
	Alg  string `json:"alg"`
}

type Payload struct {
	UserId  string `json:"userId"`
	TokenId string `json:"tokenId"`
	ExpTime int64  `json:"tokenExp"`
}

type Signature struct {
	Hash hash.Hash
}

type Token struct {
	Header  Header
	Payload Payload
	Access  string
	Refresh string
	Key     string
	Unvalid bool
	Expired bool
}

func (h *Header) ToBase64String() string {
	js, _ := json.Marshal(h)
	return base64.RawURLEncoding.EncodeToString(js)
}
func (h *Payload) ToBase64String() string {
	js, _ := json.Marshal(h)
	return base64.RawURLEncoding.EncodeToString(js)
}
func (h Signature) ToBase64String() string {
	return base64.RawURLEncoding.EncodeToString(h.Hash.Sum(nil))
}

func GenSignature(alg, data, key string) (s Signature) {
	var funcHash func() hash.Hash
	switch alg {
	case "HS512":
		funcHash = sha512.New
	default:
		funcHash = sha256.New
		alg = "HS256"
	}
	s.Hash = hmac.New(funcHash, []byte(key))
	s.Hash.Write([]byte(data))
	return s
}

func (t *Token) GenAccessToken() {
	unsigned := t.Header.ToBase64String() + "." + t.Payload.ToBase64String()
	t.Access = unsigned + "." + GenSignature(t.Header.Alg, unsigned, t.Key).ToBase64String()
}

func GenRandomHash() string {
	b := make([]byte, 10)
	rand.Read(b)
	a := base64.RawURLEncoding.EncodeToString(b)
	return GenSignature("HS256", a+a, a).ToBase64String()
}

func (t *Token) GenRefreshToken() {
	t.Refresh = GenRandomHash()
}

func (t *Token) Gen2Token() {
	t.GenAccessToken()
	t.GenRefreshToken()
}

func (t *Token) CheckAccessToken() error {
	// split token
	splitToken := strings.Split(t.Access, ".")
	if len(splitToken) != 3 {
		return errors.New("not JWT token")
	}
	// decode
	rawHeader, err := base64.RawStdEncoding.DecodeString(splitToken[0])
	if err != nil {
		return errors.New("error to decode header")
	}
	rawPayload, err := base64.RawStdEncoding.DecodeString(splitToken[1])
	if err != nil {
		return errors.New("error to decode payload")
	}
	// read json to struct
	err = json.Unmarshal(rawHeader, &t.Header)
	if err != nil {
		return errors.New("invalid header json")
	}
	err = json.Unmarshal(rawPayload, &t.Payload)
	if err != nil {
		return errors.New("invalid payload json")
	}
	// check signature
	if GenSignature(t.Header.Alg, splitToken[0]+"."+splitToken[1], t.Key).ToBase64String() != splitToken[2] {
		t.Unvalid = true
		return nil
	}
	// check espiration time
	if t.Payload.ExpTime <= time.Now().Unix() {
		t.Expired = true
		return nil
	}
	// token valid and active
	t.Unvalid = false
	t.Expired = false
	return nil
}
