package main

import (
	"afg/jwtauth/service"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type User struct {
	GUID uint64 `json:"guid"`
}

var user = User{GUID: 1}

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

	aPayload := service.Payload{UserId: "user1", TokenId: "1", ExpTime: int64((time.Minute * 10).Seconds())}
	rPayload := service.Payload{UserId: "user1", TokenId: "2", ExpTime: int64((time.Hour * 1).Seconds())}

	token := service.GenDoubleToken("HS256", "HS256", aPayload, rPayload, "key1", "key2")

	c.JSON(http.StatusOK, token)
}

func Refresh(c *gin.Context) {
	c.JSON(http.StatusOK, "u absolutely moron")
}

func main() {
	router := gin.Default()
	router.POST("/authorize", Authorize)
	router.GET("/refresh", Refresh)
	log.Fatal(router.Run(":8080"))
}
