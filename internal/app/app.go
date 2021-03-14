package app

import (
	"context"
	"strings"

	. "github.com/common-go/auth"
	. "github.com/common-go/crypto"
	"github.com/common-go/health"
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
	"github.com/teris-io/shortid"
)

var sid *shortid.Shortid
func ShortId() (string, error) {
	if sid == nil {
		s, err := shortid.New(1, shortid.DefaultABC, 2342)
		if err != nil {
			return "", err
		}
		sid = s
	}
	return sid.Generate()
}
func GenerateShortId(ctx context.Context) (string, error) {
	return ShortId()
}

type ApplicationContext struct {
	AuthenticationHandler *AuthenticationHandler
	SignOutHandler        *SignOutHandler
	PasswordHandler       *password.PasswordHandler
	SignUpHandler         *signup.SignUpHandler
	OAuth2Handler         *oauth2.OAuth2Handler
	HealthHandler         *health.HealthHandler
}

func NewApp(context context.Context, root Root) (*ApplicationContext, error) {
	db, er1 := s.Open(root.DB)
	if er1 != nil {
		return nil, er1
	}
	f := log.ErrorMsg

	generateId := GenerateShortId

	user := "user"
	authentication := "authentication"

	redisService, er2 := redisclient.NewRedisServiceByConfig(root.Redis)
	if er2 != nil {
		return nil, er2
	}
	tokenBlacklistChecker := NewTokenBlacklistChecker("blacklist:", root.Token.Expires, redisService)

	mailService := NewMailService(root.Mail)

	userInfoService := NewSqlUserInfoByConfig(db, root.AuthSqlConfig)
	bcryptComparator := &BCryptStringComparator{}
	tokenService := &DefaultTokenService{}
	verifiedCodeSender := NewVerifiedCodeEmailSender(mailService, root.Mail.From, NewTemplateLoaderByConfig(root.Auth.Template))
	passCodeService := passcode.NewPasscodeService(db, "authenpasscode", "id", "passcode", "expiredat")
	status := InitStatus(root.Status)
	authenticator := NewAuthenticatorWithTwoFactors(status, userInfoService, bcryptComparator, tokenService.GenerateToken, root.Token, root.Payload, nil, verifiedCodeSender.Send, passCodeService, root.Auth.Expires)
	authenticationHandler := NewAuthenticationHandler(authenticator.Authenticate, status.Error, status.Timeout, f)
	signOutHandler := NewSignOutHandler(tokenService.VerifyToken, root.Token.Secret, tokenBlacklistChecker.Revoke, f)

	// history := "history"
	passwordResetCode := "passwordResetCode"
	passwordRepository := password.NewSqlPasswordRepositoryByConfig(db, user, authentication, "history", root.Password.Schema)
	passResetCodeRepository := passcode.NewPasscodeService(db, passwordResetCode)
	p := root.Password
	exps := []string{p.Exp1, p.Exp2, p.Exp3, p.Exp4, p.Exp5, p.Exp6}
	signupSender := signup.NewVerifiedEmailSender(mailService, *root.SignUp.UserVerified, root.Mail.From, NewTemplateLoaderByConfig(*root.SignUp.Template))
	passwordResetSender := password.NewPasscodeEmailSender(mailService, root.Mail.From, NewTemplateLoaderByConfig(root.Password.Template.ResetTemplate))
	passwordChangeSender := password.NewPasscodeEmailSender(mailService, root.Mail.From, NewTemplateLoaderByConfig(root.Password.Template.ChangeTemplate))
	passwordService := password.NewPasswordService(bcryptComparator, passwordRepository, root.Password.ResetExpires, passResetCodeRepository, passwordResetSender.Send, tokenBlacklistChecker.RevokeAllTokens, exps, 5, nil, root.Password.ChangeExpires, passResetCodeRepository, passwordChangeSender.Send)
	passwordHandler := password.NewPasswordHandler(passwordService, f, nil)

	signUpCode := "signupCode"
	signUpRepository := signup.NewSqlSignUpRepositoryByConfig(db, user, authentication, root.SignUp.UserStatus, root.MaxPasswordAge, root.SignUp.Schema, nil)
	signUpCodeRepository := passcode.NewPasscodeService(db, signUpCode)
	signupStatus := signup.InitSignUpStatus(root.SignUp.Status)
	emailValidator := signup.NewEmailValidator(true, "")
	signUpService := signup.NewSignUpService(signupStatus, true, signUpRepository, generateId, bcryptComparator.Hash, bcryptComparator, signUpCodeRepository, signupSender.Send, root.SignUp.Expires, emailValidator.Validate, exps)
	signupHandler := signup.NewSignUpHandler(signUpService, signupStatus.Error, f, root.SignUp.Action)

	integrationConfiguration := "integrationconfiguration"
	// sources := []string{SourceGoogle, SourceFacebook, SourceLinkedIn, SourceTwitter, SourceAmazon, SourceMicrosoft, SourceDropbox}
	sources := []string{oauth2.SourceGoogle, oauth2.SourceFacebook, oauth2.SourceLinkedIn, oauth2.SourceAmazon, oauth2.SourceMicrosoft, oauth2.SourceDropbox}
	oauth2UserRepositories := make(map[string]oauth2.OAuth2UserRepository)
	oauth2UserRepositories[oauth2.SourceGoogle] = oauth2.NewGoogleUserRepository()
	oauth2UserRepositories[oauth2.SourceFacebook] = oauth2.NewFacebookUserRepository()
	//oauth2UserRepositories[oauth2.SourceLinkedIn] = oauth2.NewLinkedInUserRepository()
	// oauth2UserRepositories[SourceTwitter] = NewTwitterUserRepository(root.CallBackURL.Twitter)
	oauth2UserRepositories[oauth2.SourceAmazon] = oauth2.NewAmazonUserRepository(root.CallBackURL.Amazon)
	oauth2UserRepositories[oauth2.SourceMicrosoft] = oauth2.NewMicrosoftUserRepository(root.CallBackURL.Microsoft)
	oauth2UserRepositories[oauth2.SourceDropbox] = oauth2.NewDropboxUserRepository()

	activatedStatus := root.SignUp.UserStatus.Activated
	schema := root.OAuth2.Schema
	services := strings.Split(root.OAuth2.Services, ",")
	userRepositories := make(map[string]oauth2.UserRepository)
	for _, source := range sources {
		userRepository := oauth2.NewSqlUserRepositoryByConfig(db, user, source, activatedStatus, services, schema, oauth2.GetDriver(db), &root.UserStatus)
		userRepositories[source] = userRepository
	}
	configurationRepository := oauth2.NewSqlIntegrationConfigurationRepository(db, integrationConfiguration, oauth2UserRepositories, "status", "A")

	oauth2Service := oauth2.NewOAuth2Service(status, oauth2UserRepositories, userRepositories, configurationRepository, generateId, tokenService, root.Token, nil)
	oauth2Handler := oauth2.NewDefaultOAuth2Handler(oauth2Service, status.Error, f)

	sqlHealthChecker := s.NewHealthChecker(db)
	redisHealthChecker := redisclient.NewRedisHealthChecker(redisService.Pool, "redis", 4)
	healthServices := []health.HealthChecker{sqlHealthChecker, redisHealthChecker}

	healthHandler := health.NewHealthHandler(healthServices)

	app := ApplicationContext{
		AuthenticationHandler: authenticationHandler,
		SignOutHandler:        signOutHandler,
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
