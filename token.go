package jwtToken

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
	"sync"
	"time"
)

func GenerateToken(duration int64,signKey string, token chan string,wg *sync.WaitGroup) {
	mySigningKey := []byte(signKey)
	defer wg.Done()
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Unix() + duration,
	}

	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenKey, err := tokenClaims.SignedString(mySigningKey)
	if err != nil {
		log.Println(err)
	}
	 token <- tokenKey
}

func VerifyToken(tokenString string,signKey string) (bool, error) {
	mySigningKey := []byte(signKey)

	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return mySigningKey, nil
	})

	if err != nil {
		return false,err
	}

	if  token.Valid {
		return token.Valid, err
	} else {
		log.Println(`error => `, err)
	}
	return token.Valid, err
}


func TokenValidation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		signKey  := r.Header.Get("Signkey")
		validity, _ := VerifyToken(token,signKey)
		if validity {
			next.ServeHTTP(w, r)
		} else {
			byteOfError, _ := json.Marshal(ResponseServe(http.StatusUnauthorized, "invalid Token"))
			w.Header().Set("Content-Type", "application/json")
			w.Write(byteOfError)
		}
	})
}