package auth

import (
	"encoding/base64"
	"errors"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/dgrijalva/jwt-go"
)

type rrssUser struct {
	Id       string
	Email    string
	Password string
	FeedUrls []string
	Created  time.Time
	Deleted  time.Time
}

type customPayload struct {
	jwt.StandardClaims
}

func Validate(tokenString string) (rrssUser, error) {
	if len(tokenString) < 1 {
		return rrssUser{}, errors.New("Token must not be null or empty")
	}

	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return rrssUser{}, errors.New("Unexpected signing method")
		}
		return []byte(getSecret()), nil
	})

	user := rrssUser{}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		user.Email = claims["sub"].(string)
	} else {
		return user, errors.New("Unexpected signing method")
	}

	return user, nil
}

func Mint(email string) (string, error) {
	claims := customPayload{
		jwt.StandardClaims{
			IssuedAt:  time.Now().Local().UTC().Unix(),
			ExpiresAt: time.Now().Local().UTC().Unix() + 3600,
			Subject:   email,
			Issuer:    "RRSS",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(getSecret()))
}

// AWS copypasta
func getSecret() string {
	secretName := "dev/rrss/signingKey"
	region := "eu-central-1"

	svc := secretsmanager.New(session.New(),
		aws.NewConfig().WithRegion(region))
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"), // VersionStage defaults to AWSCURRENT if unspecified
	}

	result, err := svc.GetSecretValue(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeDecryptionFailure:
				// Secrets Manager can't decrypt the protected secret text using the provided KMS key.
				log.Println(secretsmanager.ErrCodeDecryptionFailure, aerr.Error())

			case secretsmanager.ErrCodeInternalServiceError:
				// An error occurred on the server side.
				log.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())

			case secretsmanager.ErrCodeInvalidParameterException:
				// You provided an invalid value for a parameter.
				log.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())

			case secretsmanager.ErrCodeInvalidRequestException:
				// You provided a parameter value that is not valid for the current state of the resource.
				log.Println(secretsmanager.ErrCodeInvalidRequestException, aerr.Error())

			case secretsmanager.ErrCodeResourceNotFoundException:
				// We can't find the resource that you asked for.
				log.Println(secretsmanager.ErrCodeResourceNotFoundException, aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Println(err.Error())
		}
	}

	var secretString, decodedBinarySecret string
	if result.SecretString != nil {
		secretString = *result.SecretString
		return secretString
	} else {
		decodedBinarySecretBytes := make([]byte, base64.StdEncoding.DecodedLen(len(result.SecretBinary)))
		len, err := base64.StdEncoding.Decode(decodedBinarySecretBytes, result.SecretBinary)
		if err != nil {
			log.Println("Base64 Decode Error:", err)
		}
		decodedBinarySecret = string(decodedBinarySecretBytes[:len])
		return decodedBinarySecret
	}
}
