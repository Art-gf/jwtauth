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

var storage db.MongoDB
var CFG sv.ConfigService

func main() {
	// read config
	if err := sv.ReadConfig("/config.json", &CFG); err != nil {
		log.Fatal(err)
	}
	// initial database connection
	ctx := context.TODO()
	storage = db.InitDB(CFG.DB_URI)
	if err := storage.Connect(ctx); err != nil {
		log.Fatal("Unable to make db connection " + err.Error())
	}
	storage.OpenDB(CFG.DB_NAME)
	storage.OpenCollection(CFG.DB_COLL)
	// initial server
	client := sv.NewInstance()
	client.Mux.HandleFunc("/register", Register)
	client.Mux.HandleFunc("/login", Login)
	client.Mux.HandleFunc("/authorize", Authorize)
	client.Mux.HandleFunc("/refresh", Refresh)
	if err := client.Start(CFG.SERVER_URI); err != nil {
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
	newUser := sv.NewUser(requestMessage.Login, requestMessage.Pass, CFG.SECRET_KEY)
	ctx := context.TODO()
	if storage.FindDoc(CFG.DB_COLL, ctx, sv.User{Login: newUser.Login}) == nil {
		sv.MessResp(w, http.StatusNotAcceptable, "This user already exist")
		return
	}
	storage.WriteDoc(CFG.DB_COLL, ctx, newUser)
	sv.MessResp(w, http.StatusOK, "User registered")
}

func Login(w http.ResponseWriter, r *http.Request) {
	// read JSON
	requestMessage := sv.LoginRequest{}
	if sv.FromNet(r, w, &requestMessage) != nil {
		return
	}
	// find user on database and read information for response user guid
	regUser := sv.User{Login: requestMessage.Login}
	if findUser(&regUser) != nil {
		sv.MessResp(w, http.StatusNotAcceptable, "This user login not registered")
		return
	}
	// check password
	if !sv.CheckUserHash(regUser.UserHash, requestMessage.Login, requestMessage.Pass, CFG.SECRET_KEY) {
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
	regUser := sv.User{Guid: requestMessage.Guid}
	if findUser(&regUser) != nil {
		sv.MessResp(w, http.StatusNotAcceptable, "This user guid not registered")
		return
	}
	// generate access and refresh token
	accessToken, refreshToken, err := genToken(regUser)
	if err != nil {
		sv.MessResp(w, http.StatusInternalServerError, "Cant register token on server")
		return
	}
	sv.ToNet(w, http.StatusOK, sv.AuthorizeResponse{AccessToken: accessToken, RefreshToken: refreshToken})
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	// read JSON
	dataUser := sv.RefreshRequest{}
	if sv.FromNet(r, w, &dataUser) != nil {
		return
	}
	// check token
	payloadAt, statusAt, err := sv.CheckAccessToken(dataUser.AccessToken, CFG.SECRET_KEY)
	if err != nil {
		sv.MessResp(w, http.StatusUnprocessableEntity, "Error "+err.Error())
		return
	}
	payloadRt, statusRt, err := sv.CheckRefreshToken(dataUser.AccessToken, dataUser.RefreshToken, CFG.SECRET_KEY)
	if err != nil {
		sv.MessResp(w, http.StatusUnprocessableEntity, "Error "+err.Error())
		return
	}
	// find user guid in database from payload info
	regUser := sv.User{Guid: payloadAt.Guid}
	if findUser(&regUser) != nil {
		sv.MessResp(w, http.StatusNotAcceptable, "This user guid on token info is not found")
		return
	}
	// check refresh token on db
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
		// generate access and refresh token
		accessToken, refreshToken, err := genToken(regUser)
		if err != nil {
			sv.MessResp(w, http.StatusInternalServerError, "Cant register token on server")
			return
		}

		sv.ToNet(w, http.StatusOK, sv.RefreshResponse{
			Message:      "Token updated",
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
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

func genToken(u sv.User) (at, rt string, err error) {
	ctx := context.TODO()
	accessToken := sv.GenAccessToken(sv.TokenPayload{Guid: u.Guid, ExpTime: sv.PayloadMinute(CFG.ACCESS_EXP)}, CFG.SECRET_KEY)
	refreshToken := accessToken.GenRefreshToken(sv.TokenPayload{Guid: u.Guid, ExpTime: sv.PayloadMinute(CFG.REFRESH_EXP)}, CFG.SECRET_KEY)
	err = storage.UpdateDoc(CFG.DB_COLL, ctx, sv.User{Guid: u.Guid}, sv.User{RefreshHash: sv.BcryptHash(refreshToken.ReturnString())})
	return accessToken.ReturnString(), refreshToken.ReturnString(), err
}

func findUser(u interface{}) error {
	ctx := context.TODO()
	if err := storage.FindDoc(CFG.DB_COLL, ctx, u); err != nil {
		return err
	}
	storage.ReadDoc(CFG.DB_COLL, ctx, u, u)
	return nil
}
