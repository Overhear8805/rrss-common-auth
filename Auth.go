package auth

import (
	"errors"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/dgrijalva/jwt-go"
)

var userTable = aws.String("rrss-users")

type RrssUser struct {
	Id       string
	Email    string
	Password string
	FeedUrls []string
	Created  time.Time
	Deleted  time.Time
}

type CustomPayload struct {
	jwt.StandardClaims
}

var mySigningKey = []byte("e4Mc8nxQU185ZAVJHxYp5BdsXqrTTbsFShPsCKj481JBbwSf8EqzvDi9Gso1lonnzb45T0Va2IIkBWR0UeMNzpRmRn120KgBV4DYtV7rPOXmeavhFw2X5Xl8KmJjgmwAREqsqn6pPPnhZP2Ye3c44x2lyoh3jYzKO3DT8hxvgVbrFlro0hstV1vxNqfuVR7iq7JCvihQqXjQzOPY7R4P90NtEd9WUg5M2PueNALkqWZG6BBNvmkVS1a7P6esI8Bq")

func Validate(tokenString string) (RrssUser, error) {
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return RrssUser{}, errors.New("Unexpected signing method")
		}
		return mySigningKey, nil
	})

	user := RrssUser{}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		user.Email = claims["sub"].(string)
	} else {
		return user, errors.New("Unexpected signing method")
	}

	return user, nil
}

func Mint(email string) (string, error) {
	// Create the Claims
	claims := CustomPayload{
		jwt.StandardClaims{
			IssuedAt:  time.Now().Local().UTC().Unix(),
			ExpiresAt: time.Now().Local().UTC().Unix() + 3600,
			Subject:   email,
			Issuer:    "RRSS",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(mySigningKey)
}
