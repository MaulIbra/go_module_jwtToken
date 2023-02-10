package jwtToken

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

func GenerateToken(duration int64) string {
	mySigningKey := []byte("SignKey")

	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Unix() + duration,
	}

	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenKey, err := tokenClaims.SignedString(mySigningKey)
	if err != nil {
		log.Println(err)
	}
	return tokenKey
}

func VerifyToken(tokenString string) (bool, error) {
	mySigningKey := []byte("SignKey")

	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return mySigningKey, nil
	})

	if err != nil {
		return false, err
	}

	if token.Valid {
		return token.Valid, err
	} else {
		log.Println(`error => `, err)
	}
	return token.Valid, err
}

func TokenValidation() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.Request.Header["Authorization"]) == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "you are not unauthorized",
			})
			c.Abort()
			return
		} else {
			token := c.Request.Header["Authorization"][0]
			validity, _ := VerifyToken(token)
			if validity {
				c.Next()
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error": "you are not unauthorized",
				})
				c.Abort()
				return
			}
		}
	}
}
