package auth

import (
	"errors"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
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

type Response events.APIGatewayProxyResponse

var mySigningKey = []byte("e4Mc8nxQU185ZAVJHxYp5BdsXqrTTbsFShPsCKj481JBbwSf8EqzvDi9Gso1lonnzb45T0Va2IIkBWR0UeMNzpRmRn120KgBV4DYtV7rPOXmeavhFw2X5Xl8KmJjgmwAREqsqn6pPPnhZP2Ye3c44x2lyoh3jYzKO3DT8hxvgVbrFlro0hstV1vxNqfuVR7iq7JCvihQqXjQzOPY7R4P90NtEd9WUg5M2PueNALkqWZG6BBNvmkVS1a7P6esI8Bq")

// Connect to DynamoDB
var sess = session.Must(session.NewSessionWithOptions(
	session.Options{SharedConfigState: session.SharedConfigEnable},
))
var svc = dynamodb.New(sess)

func MintJwt(email string, password string) (string, error) {
	userResult, err := getUser(email)
	if err != nil {
		return "", err
	}

	existingUser := RrssUser{}
	err = dynamodbattribute.UnmarshalMap(userResult.Item, &existingUser)
	if err != nil {
		return "", err
	}

	if password != existingUser.Password {
		return "", errors.New("Invalid password")
	}
	validatedUser := existingUser

	// Create the Claims
	claims := CustomPayload{
		jwt.StandardClaims{
			IssuedAt:  time.Now().Local().UTC().Unix(),
			ExpiresAt: time.Now().Local().UTC().Unix() + 3600,
			Subject:   validatedUser.Email,
			Issuer:    "RRSS",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(mySigningKey)
}

func getUser(email string) (*dynamodb.GetItemOutput, error) {
	return svc.GetItem(&dynamodb.GetItemInput{
		TableName: userTable,
		Key: map[string]*dynamodb.AttributeValue(map[string]*dynamodb.AttributeValue{
			"Email": {
				S: aws.String(email),
			},
		}),
	})
}
