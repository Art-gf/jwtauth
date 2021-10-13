package service

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
)

type ConfigService struct {
	SERVER_URI  string `json:"server_uri"`
	DB_URI      string `json:"db_uri"`
	DB_NAME     string `json:"db_name"`
	DB_COLL     string `json:"db_collections"`
	ACCESS_EXP  int    `json:"jwt_access_exp"`
	REFRESH_EXP int    `json:"jwt_refresh_exp"`
	SECRET_KEY  string `json:"secret_key"`
}

func ReadConfig(path string, i interface{}) (err error) {
	ex, err := os.Executable()
	if err != nil {
		return
	}
	cfgFile, err := os.Open(filepath.Dir(ex) + path)
	if err != nil {
		return
	}
	cfgByte, err := ioutil.ReadAll(cfgFile)
	if err != nil {
		return
	}
	if err = cfgFile.Close(); err != nil {
		return
	}
	if err = json.Unmarshal(cfgByte, i); err != nil {
		return
	}
	return nil
}
