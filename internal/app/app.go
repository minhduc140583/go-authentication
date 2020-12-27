package app

import (
	"context"
	. "github.com/common-go/auth"
	. "github.com/common-go/crypto"
	. "github.com/common-go/health"
	. "github.com/common-go/jwt"
	"github.com/common-go/log"
	. "github.com/common-go/mail"
	"github.com/common-go/oauth2"
	"github.com/common-go/passcode"
	"github.com/common-go/password"
	redisclient "github.com/common-go/redis"
	"github.com/common-go/sendgrid"
	"github.com/common-go/signup"
	"github.com/common-go/smtp"
	s "github.com/common-go/sql"
	_ "github.com/go-sql-driver/mysql"
	"strings"
)

type ApplicationContext struct {
	AuthenticationHandler *AuthenticationHandler
	SignOutHandler        *SignOutHandler
	PasswordHandler       *password.PasswordHandler
	SignUpHandler         *signup.SignUpHandler
	OAuth2Handler         *oauth2.OAuth2Handler
	HealthHandler         *HealthHandler
}

func NewApp(context context.Context, root Root) (*ApplicationContext, error) {
	db, er1 := s.Open(root.DB)
	if er1 != nil {
		return nil, er1
	}
	f := log.ErrorMsg

	oauth2UserRepositories := make(map[string]oauth2.OAuth2UserRepository)
	oauth2UserRepositories[oauth2.SourceGoogle] = oauth2.NewGoogleUserRepository()
	oauth2UserRepositories[oauth2.SourceFacebook] = oauth2.NewFacebookUserRepository()
	//oauth2UserRepositories[oauth2.SourceLinkedIn] = oauth2.NewLinkedInUserRepository()
	// oauth2UserRepositories[SourceTwitter] = NewTwitterUserRepository(root.CallBackURL.Twitter)
	oauth2UserRepositories[oauth2.SourceAmazon] = oauth2.NewAmazonUserRepository(root.CallBackURL.Amazon)
	oauth2UserRepositories[oauth2.SourceMicrosoft] = oauth2.NewMicrosoftUserRepository(root.CallBackURL.Microsoft)
	oauth2UserRepositories[oauth2.SourceDropbox] = oauth2.NewDropboxUserRepository()

	activatedStatus := root.SignUp.Status.Activated
	schema := root.OAuth2.Schema
	services := strings.Split(root.OAuth2.Services, ",")
	userRepositories := make(map[string]oauth2.UserRepository)
	user := "user"
	authentication := "authentication"
	// history := "history"
	signUpCode := "signupCode"
	passwordResetCode := "passwordResetCode"
	integrationConfiguration := "integrationconfiguration"
	// sources := []string{SourceGoogle, SourceFacebook, SourceLinkedIn, SourceTwitter, SourceAmazon, SourceMicrosoft, SourceDropbox}
	sources := []string{oauth2.SourceGoogle, oauth2.SourceFacebook, oauth2.SourceLinkedIn, oauth2.SourceAmazon, oauth2.SourceMicrosoft, oauth2.SourceDropbox}

	redisService, er2 := redisclient.NewRedisServiceByConfig(root.Redis)
	if er2 != nil {
		return nil, er2
	}
	tokenBlacklistChecker := NewTokenBlacklistChecker("blacklist:", root.Token.Expires, redisService)

	signUpRepository := signup.NewSqlSignUpRepositoryByConfig(db, user, authentication, root.SignUp.Status, root.MaxPasswordAge, root.SignUp.Schema, nil)
	signUpCodeRepository := passcode.NewDefaultPasscodeService(db, signUpCode)
	passwordRepository := password.NewSqlPasswordRepositoryByConfig(db, user, authentication, "history", root.Password.Schema)
	passResetCodeRepository := passcode.NewDefaultPasscodeService(db, passwordResetCode)

	for _, source := range sources {
		userRepository := oauth2.NewSqlUserRepositoryByConfig(db, user, source, activatedStatus, services, schema, nil, oauth2.GetDriver(db))
		userRepositories[source] = userRepository
	}
	configurationRepository := oauth2.NewSqlIntegrationConfigurationRepository(db, integrationConfiguration, oauth2UserRepositories, "status", "A")

	mailService := NewMailService(root.Mail)

	userInfoService := NewSqlUserInfoByConfig(db, root.AuthSqlConfig)
	bcryptComparator := &BCryptStringComparator{}
	tokenService := &DefaultTokenService{}

	p := root.Password
	exps := []string{p.Exp1, p.Exp2, p.Exp3, p.Exp4, p.Exp5, p.Exp6}
	signupSender := signup.NewVerifiedEmailSender(mailService, *root.SignUp.UserVerified, root.Mail.From, NewTemplateLoaderByConfig(*root.SignUp.Template))
	passwordResetSender := password.NewPasscodeEmailSender(mailService, root.Mail.From, NewTemplateLoaderByConfig(root.Password.Template.ResetTemplate))
	passwordChangeSender := password.NewPasscodeEmailSender(mailService, root.Mail.From, NewTemplateLoaderByConfig(root.Password.Template.ChangeTemplate))
	verifiedCodeSender := NewVerifiedCodeEmailSender(mailService, root.Mail.From, NewTemplateLoaderByConfig(root.Auth.Template))
	passCodeService := passcode.NewPasscodeService(db, "authenpasscode", "id", "passcode", "expiredat")
	authenticator := NewDefaultAuthenticator(userInfoService, bcryptComparator, nil, tokenService, root.Token, root.Payload, false, root.Auth.Expires, passCodeService, verifiedCodeSender, nil)
	passwordService := password.NewPasswordService(bcryptComparator, passwordRepository, root.Password.ResetExpires, passResetCodeRepository, passwordResetSender, tokenBlacklistChecker, exps, 5, nil, root.Password.ChangeExpires, passResetCodeRepository, passwordChangeSender, nil)

	userIdGenerator := signup.NewUserIdGenerator(true)
	emailValidator := signup.NewEmailValidator(true, "")
	signUpService := signup.NewSignUpService(true, signUpRepository, userIdGenerator, bcryptComparator, bcryptComparator, signUpCodeRepository, signupSender, root.SignUp.Expires, emailValidator, exps, nil)

	oauth2Service := oauth2.NewOAuth2Service(oauth2UserRepositories, userRepositories, configurationRepository, userIdGenerator, tokenService, root.Token, root.Status, nil, nil)

	authenticationHandler := NewAuthenticationHandler(authenticator, f, nil, nil)
	signoutHandler := NewDefaultSignOutHandler(tokenService, root.Token.Secret, tokenBlacklistChecker, nil)
	passwordHandler := password.NewPasswordHandler(passwordService, nil, f, nil)
	signupHandler := &signup.SignUpHandler{SignUpService: signUpService}
	oauth2Handler := oauth2.NewOAuth2Handler(oauth2Service, nil, f, nil)

	sqlHealthChecker := s.NewHealthChecker(db)
	redisHealthChecker := redisclient.NewRedisHealthChecker(redisService.Pool, "redis", 4)
	healthServices := []HealthChecker{sqlHealthChecker, redisHealthChecker}

	healthHandler := NewHealthHandler(healthServices)

	app := ApplicationContext{
		AuthenticationHandler: authenticationHandler,
		SignOutHandler:        signoutHandler,
		PasswordHandler:       passwordHandler,
		SignUpHandler:         signupHandler,
		OAuth2Handler:         oauth2Handler,
		HealthHandler:         healthHandler,
	}
	return &app, nil
}

func NewMailService(mailConfig MailConfig) SimpleMailSender {
	if mailConfig.Provider == "sendgrid" {
		return NewSimpleMailSender(sendgrid.NewSendGridMailSender(mailConfig.SendGridAPIkey))
	}
	return NewSimpleMailSender(smtp.NewSmtpMailSender(mailConfig.Smtp))
}
