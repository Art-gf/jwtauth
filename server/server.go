package main

import (
	//"afg/jwtauth/service"
	"afg/jwtauth/service"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	router = gin.Default()
)

type User struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

var user = User{
	ID:       1,
	Username: "username",
	Password: "password",
}

func Login(c *gin.Context) {
	var u User

	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}
	//compare the user from the request, with the one we defined:
	if user.Username != u.Username || user.Password != u.Password {
		c.JSON(http.StatusUnauthorized, "Please provide valid login details")
		return
	}

	aPayload := service.Payload{UserId: "user1", TokenId: "1", ExpTime: int64((time.Minute * 10).Seconds())}
	rPayload := service.Payload{UserId: "user1", TokenId: "2", ExpTime: int64((time.Hour * 1).Seconds())}

	token := service.GenDoubleToken("HS256", "HS256", aPayload, rPayload, "key1", "key2")

	c.JSON(http.StatusOK, token)
}

func main() {
	router.POST("/login", Login)
	log.Fatal(router.Run(":8080"))
}
