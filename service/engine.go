package service

import (
	tp "afg/jwtauth/templates"
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

func (s ServerInstance) Start(addr string) {
	http.ListenAndServe(addr, s.Mux)
}

func ToNet(w http.ResponseWriter, i interface{}) {
	mJ, _ := json.Marshal(i)
	w.Write(mJ)
}

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

func MessResp(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	ToNet(w, tp.ErrorMessage{Message: msg})
}
