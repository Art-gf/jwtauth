package main

import (
	"afg/jwtauth/service"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type User struct {
	GUID uint64 `json:"guid"`
}

type TrustedUser struct {
	AccessToken string `json:"accessToken"`
}

var user = User{GUID: 1}
var key1 string = "key1"
var key2 string = "key2"

func Authorize(c *gin.Context) {
	var u User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}
	if user.GUID != u.GUID {
		c.JSON(http.StatusUnauthorized, "This user not found")
		return
	}

	token := service.Token{}
	token.Header = service.Header{Type: "jwt", Alg: "HS512"}
	token.Payload = service.Payload{UserId: "user1", TokenId: "1", ExpTime: time.Now().Add(time.Minute * 10).Unix()}
	token.Key = key1
	token.Gen2Token()

	c.JSON(http.StatusOK, map[string]string{"access": token.Access, "refresh": token.Refresh})
}

func Refresh(c *gin.Context) {
	c.JSON(http.StatusOK, "u absolutely moron")
}

func Check(c *gin.Context) {
	var tU TrustedUser
	if err := c.ShouldBindJSON(&tU); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}

	userToken := service.Token{Access: tU.AccessToken, Key: key1}
	if err := userToken.CheckAccessToken(); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]string{"tokenValid": fmt.Sprint(!userToken.Unvalid),
		"tokenExpired": fmt.Sprint(userToken.Expired),
		"timeLeft":     fmt.Sprint(userToken.Payload.ExpTime - time.Now().Unix()),
	})

}

func main() {
	router := gin.Default()
	router.POST("/authorize", Authorize)
	router.GET("/refresh", Refresh)
	router.POST("/check", Check)
	log.Fatal(router.Run(":8080"))

}
