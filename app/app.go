package app

import (
	"net/http"
	u "lens/utils"
	"strings"
	"go-contacts/models"
	jwt "github.com/dgrijalva/jwt-go"
	"os"
	"context"
	"fmt"
)

var JwtAuthentication = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Auth free endpoints
		notAuth := []string{"/api/user/new", "/api/user/login"}
		// Current request path
		requestPath := r.URL.Path

		// check if endpoint does not require auth
		for _, value := range notAuth {
			if value == requestPath {
				next.ServeHTTP(w, r)
				return 
			}
		}

		response := make(map[string] interface{})
		tokenHeader := r.Header.Get("Authorization")

		// return 403 if no token
		if tokenHeader == "" {
			response = u.Message(false, "Missing authentication token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		// Check for malformed token
		if len(splitted) != 2 {
			response = u.Message(false, "Bad or malformed token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		// Get token value
		tokenValue := splitted[1]
		tk := &models.Token{}

		token, err := jwt.ParseWithClaims(tokenValue, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("token_password")), nil
		})

		if err != nil { //Malformed token, returns with http code 403 as usual
			response = u.Message(false, "Malformed authentication token")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		if !token.Valid { //Token is invalid, maybe not signed on this server
			response = u.Message(false, "Token is not valid.")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		//Everything went well, proceed with the request and set the caller to the user retrieved from the parsed token
		fmt.Sprintf("User %", tk.Username) //Useful for monitoring
		ctx := context.WithValue(r.Context(), "user", tk.UserId)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r) //proceed in the middleware chain!
	});
}