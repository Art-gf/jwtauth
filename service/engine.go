package service

// import (
// 	"context"
// 	"io"
// 	"net/http"
// 	"os"
// 	"os/signal"
// 	"time"

// 	"golang.org/x/crypto/acme/autocert"
// )

// type ServerInstance struct {
// 	Mux http.ServeMux
// }

// func logn(a http.ResponseWriter, b *http.Request) {
// }

// func out() {
// 	inst := new(ServerInstance)

// 	inst.Mux.HandleFunc("/login", logn)

// 	mux := http.NewServeMux()

// 	mux.HandleFunc("/login", logn)

// 	http.ListenAndServe(":8080", mux)

// }
