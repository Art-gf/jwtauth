package main

import (
	"afg/jwtauth/service"
	"log"
	"net/http"

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
	token, err := service.CreateJwtHmacString("HS256", service.Payload{UserId: "user1"}, "key")
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	c.JSON(http.StatusOK, token)
}

func main() {
	router.POST("/login", Login)
	log.Fatal(router.Run(":8080"))
}
