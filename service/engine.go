package service

// Server engine

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

type ServerInstance struct {
	Mux *http.ServeMux
}

func NewInstance() (s ServerInstance) {
	s.Mux = http.NewServeMux()
	return
}

func (s ServerInstance) Start(addr string) error {
	return http.ListenAndServe(addr, s.Mux)
}

// response JSON
func ToNet(w http.ResponseWriter, status int, i interface{}) {
	mJ, _ := json.Marshal(i)
	w.WriteHeader(http.StatusOK)
	w.Write(mJ)
}

// request JSON
func FromNet(r *http.Request, w http.ResponseWriter, i interface{}) error {
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		MessResp(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return err
	}
	err = json.Unmarshal(b, i)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		MessResp(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
	}
	return err
}

// simple message
func MessResp(w http.ResponseWriter, status int, msg string) {
	ToNet(w, status, ErrorMessage{Message: msg})
}
