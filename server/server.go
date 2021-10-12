package main

import (
	db "afg/jwtauth/database"
	sv "afg/jwtauth/service"
	tp "afg/jwtauth/templates"
	"context"
	"net/http"
)

// "afg/jwtauth/database"
// "afg/jwtauth/service"
// "afg/jwtauth/templates"

const SERVER_URI string = ":8080"
const KEY string = "key1"
const DB_URI string = "mongodb://localhost:27017/"
const DB string = "authorize"
const DB_USER string = "users"

type ErrorMessage struct {
	Message string `json:"Message"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	dataUser := tp.RegisterRequest{}
	if sv.FromNet(r, w, &dataUser) != nil {
		return
	}

	newUser := tp.User{
		Login:       dataUser.Name,
		Guid:        sv.CreateGuid(),
		UserHash:    sv.MakeUserHash(dataUser.Name, dataUser.Pass, KEY),
		RefreshHash: "empty",
	}

	ctx := context.TODO()
	storage.OpenDB(DB)
	storage.OpenCollection(DB_USER)

	if storage.FindDoc(DB_USER, ctx, tp.User{Login: newUser.Login}) {

		sv.MessResp(w, http.StatusNotAcceptable, "This user already exist")
		return
	}
	storage.WriteDoc(DB_USER, ctx, newUser)
	sv.MessResp(w, http.StatusOK, "User registered")

}

var storage db.MongoDB

func main() {

	ctx := context.TODO()
	storage = db.InitDB(DB_URI)
	storage.Connect(ctx)

	client := sv.NewInstance()
	client.Mux.HandleFunc("/register", Register)
	client.Start(SERVER_URI)

}
