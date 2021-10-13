package main

import (
	db "afg/jwtauth/database"
	sv "afg/jwtauth/service"
	"context"
	"fmt"
	"log"
	"net/http"
	"time"
)

// "afg/jwtauth/database"
// "afg/jwtauth/service"
// "afg/jwtauth/templates"

const SERVER_URI string = ":8080"
const KEY string = "key1"
const DB_URI string = "mongodb://localhost:27017/"
const DB string = "authorize"
const DB_USER string = "users"
const MIN_ACCESS int = 1
const MIN_REFRESH int = 2

type ErrorMessage struct {
	Message string `json:"Message"`
}

var storage db.MongoDB

func main() {
	// initial database connection
	ctx := context.TODO()
	storage = db.InitDB(DB_URI)
	if err := storage.Connect(ctx); err != nil {
		log.Fatal("Unable to make db connection " + err.Error())
	}
	storage.OpenDB(DB)
	storage.OpenCollection(DB_USER)
	// initial server
	client := sv.NewInstance()
	client.Mux.HandleFunc("/register", Register)
	client.Mux.HandleFunc("/login", Login)
	client.Mux.HandleFunc("/authorize", Authorize)
	client.Mux.HandleFunc("/refresh", Refresh)
	if err := client.Start(SERVER_URI); err != nil {
		log.Fatal("Unable server start " + err.Error())
	}
}

func Register(w http.ResponseWriter, r *http.Request) {
	// read JSON
	requestMessage := sv.RegisterRequest{}
	if sv.FromNet(r, w, &requestMessage) != nil {
		return
	}
	// register new user and write to database
	newUser := sv.NewUser(requestMessage.Login, requestMessage.Pass, KEY)
	ctx := context.TODO()
	if storage.FindDoc(DB_USER, ctx, sv.User{Login: newUser.Login}) {
		sv.MessResp(w, http.StatusNotAcceptable, "This user already exist")
		return
	}
	storage.WriteDoc(DB_USER, ctx, newUser)

	sv.MessResp(w, http.StatusOK, "User registered")
}

func Login(w http.ResponseWriter, r *http.Request) {
	// read JSON
	requestMessage := sv.LoginRequest{}
	if sv.FromNet(r, w, &requestMessage) != nil {
		return
	}
	// find user on database and read information for response user guid
	ctx := context.TODO()
	if !storage.FindDoc(DB_USER, ctx, sv.User{Login: requestMessage.Login}) {
		sv.MessResp(w, http.StatusNotAcceptable, "This user login not registered")
		return
	}
	regUser := sv.User{Login: requestMessage.Login}
	storage.ReadDoc(DB_USER, ctx, regUser, &regUser)
	if !sv.CheckUserHash(regUser.UserHash, requestMessage.Login, requestMessage.Pass, KEY) {
		sv.MessResp(w, http.StatusNotAcceptable, "Incorrect password")
		return
	}

	sv.ToNet(w, http.StatusOK, sv.LoginResponse{Guid: regUser.Guid})
}

func Authorize(w http.ResponseWriter, r *http.Request) {
	// read JSON
	requestMessage := sv.AuthorizeRequest{}
	if sv.FromNet(r, w, &requestMessage) != nil {
		return
	}
	// find user on database and read information for generate token payload
	ctx := context.TODO()
	if !storage.FindDoc(DB_USER, ctx, sv.User{Guid: requestMessage.Guid}) {
		sv.MessResp(w, http.StatusNotAcceptable, "This user guid not registered")
		return
	}
	regUser := sv.User{Guid: requestMessage.Guid}
	storage.ReadDoc(DB_USER, ctx, regUser, &regUser)
	// generate access and refresh token
	accessToken := sv.GenAccessToken(sv.TokenHeader{Type: "JWT", Alg: "HS512"}, sv.TokenPayload{Guid: regUser.Guid, ExpTime: time.Now().Add(time.Minute * time.Duration(MIN_ACCESS)).Unix()}, KEY)
	refreshToken := accessToken.GenRefreshToken(sv.TokenPayload{Guid: regUser.Guid, ExpTime: time.Now().Add(time.Minute * time.Duration(MIN_REFRESH)).Unix()}, KEY)
	if !storage.UpdateDoc(DB_USER, ctx, sv.User{Guid: requestMessage.Guid}, sv.User{RefreshHash: sv.BcryptHash(refreshToken.ReturnString())}) {
		sv.MessResp(w, http.StatusInternalServerError, "Cant register token on server")
		return
	}

	sv.ToNet(w, http.StatusOK, sv.AuthorizeResponse{AccessToken: accessToken.ReturnString(), RefreshToken: refreshToken.ReturnString()})
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	// read JSON
	dataUser := sv.RefreshRequest{}
	if sv.FromNet(r, w, &dataUser) != nil {
		return
	}
	// split token
	splitAt, err := sv.SplitToken(dataUser.AccessToken)
	if err != nil {
		sv.MessResp(w, http.StatusInternalServerError, "Unsupported access token structure")
		return
	}
	splitRt, err := sv.SplitToken(dataUser.RefreshToken)
	if err != nil {
		sv.MessResp(w, http.StatusInternalServerError, "Unsupported refresh token structure")
		return
	}
	// check token
	statusAt, err := sv.CheckAccessToken(splitAt, KEY)
	if err != nil {
		sv.MessResp(w, http.StatusUnprocessableEntity, "Error "+err.Error())
		return
	}
	statusRt, err := sv.CheckRefreshToken(splitAt, splitRt, KEY)
	if err != nil {
		sv.MessResp(w, http.StatusUnprocessableEntity, "Error "+err.Error())
		return
	}
	// read payload info
	payloadAt := sv.TokenPayload{}
	err = sv.DecodeString(splitAt[1], &payloadAt)
	if err != nil {
		sv.MessResp(w, http.StatusInternalServerError, "Error decode access expiration time")
		return
	}
	payloadRt := sv.TokenPayload{}
	err = sv.DecodeString(splitRt[0], &payloadRt)
	if err != nil {
		sv.MessResp(w, http.StatusInternalServerError, "Error decode refresh expiration time")
		return
	}
	// find user guid in database from payload info
	ctx := context.TODO()
	if !storage.FindDoc(DB_USER, ctx, sv.User{Guid: payloadAt.Guid}) {
		sv.MessResp(w, http.StatusNotAcceptable, "This user guid on token info is not found")
		return
	}
	regUser := sv.User{Guid: payloadAt.Guid}
	storage.ReadDoc(DB_USER, ctx, regUser, &regUser)
	if !sv.BcryptCompare(dataUser.RefreshToken, regUser.RefreshHash) {
		sv.MessResp(w, http.StatusNotAcceptable, "Unregistered token")
		return
	}
	// if both token not expired, dont generate new tokens
	if statusAt && statusRt {
		sv.ToNet(w, http.StatusOK,
			sv.RefreshResponse{
				Message:      "Both tokens is active, time to left, s",
				AccessToken:  fmt.Sprint(payloadAt.ExpTime - time.Now().Unix()),
				RefreshToken: fmt.Sprint(payloadRt.ExpTime - time.Now().Unix()),
			})
		return
	}
	// if access token expired but refresh token valid - generate new access and refresh tokens
	if !statusAt && statusRt {
		accessToken := sv.GenAccessToken(sv.TokenHeader{Type: "JWT", Alg: "HS512"}, sv.TokenPayload{Guid: regUser.Guid, ExpTime: time.Now().Add(time.Minute * time.Duration(MIN_ACCESS)).Unix()}, KEY)
		refreshToken := accessToken.GenRefreshToken(sv.TokenPayload{Guid: regUser.Guid, ExpTime: time.Now().Add(time.Minute * time.Duration(MIN_REFRESH)).Unix()}, KEY)
		if !storage.UpdateDoc(DB_USER, ctx, sv.User{Guid: payloadAt.Guid}, sv.User{RefreshHash: sv.BcryptHash(refreshToken.ReturnString())}) {
			sv.MessResp(w, http.StatusInternalServerError, "Cant register token on server")
			return
		}

		sv.ToNet(w, http.StatusOK, sv.RefreshResponse{
			Message:      "Token updated",
			AccessToken:  accessToken.ReturnString(),
			RefreshToken: refreshToken.ReturnString(),
		})
		return
	}
	// if both token is expired don provide new tokens
	if !statusAt && !statusRt {
		sv.ToNet(w, http.StatusOK, sv.RefreshResponse{
			Message:      "Refresh token expired, try to login",
			AccessToken:  "-",
			RefreshToken: "-",
		})
		return
	}
	// if access token active and refresh expired... this is unacceptable situation u know..
	sv.ToNet(w, http.StatusBadRequest, sv.RefreshResponse{
		Message:      "Error, try to hack another service",
		AccessToken:  "-",
		RefreshToken: "-",
	})
}
