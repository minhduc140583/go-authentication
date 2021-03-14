package app

import (
	"context"
	"github.com/gorilla/mux"
)

const (
	GET = "GET"
	POST = "POST"
	PUT = "PUT"
	DELETE = "DELETE"
)

func Route(r *mux.Router, context context.Context, root Root) error {
	app, err := NewApp(context, root)
	if err != nil {
		return err
	}

	r.HandleFunc("/authentication/authenticate", app.AuthenticationHandler.Authenticate).Methods(POST)
	r.HandleFunc("/authentication/signout/{username}", app.SignOutHandler.SignOut).Methods(GET)

	r.HandleFunc("/password/change", app.PasswordHandler.ChangePassword).Methods(POST)
	r.HandleFunc("/password/forgot", app.PasswordHandler.ForgotPassword).Methods(POST)
	r.HandleFunc("/password/reset", app.PasswordHandler.ResetPassword).Methods(POST)

	r.HandleFunc("/signup/signup", app.SignUpHandler.SignUp).Methods(POST)
	r.HandleFunc("/signup/verify/{userId}/{code}", app.SignUpHandler.VerifyUser).Methods(GET)

	r.HandleFunc("/oauth2/configurations/{type}", app.OAuth2Handler.Configuration).Methods(GET)
	r.HandleFunc("/oauth2/configurations", app.OAuth2Handler.Configurations).Methods(GET)
	r.HandleFunc("/oauth2/authenticate", app.OAuth2Handler.Authenticate).Methods(POST)

	return err
}
