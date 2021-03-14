package app

import (
	"github.com/common-go/auth"
	"github.com/common-go/mail"
	"github.com/common-go/oauth2"
	"github.com/common-go/password"
	redisclient "github.com/common-go/redis"
	"github.com/common-go/signup"
	"github.com/common-go/smtp"
	"github.com/common-go/sql"
)

type Root struct {
	Server ServerConfig       `mapstructure:"server"`
	DB     sql.DatabaseConfig `mapstructure:"db"`
	Redis  redisclient.Config `mapstructure:"redis"`

	MaxPasswordFailed     int                                  `mapstructure:"max_password_failed"`
	LockedMinutes         int                                  `mapstructure:"locked_minutes"`
	MaxPasswordAge        int                                  `mapstructure:"max_password_age"`
	PasswordEncryptionKey string                               `mapstructure:"password_encryption_key"`
	Token                 auth.TokenConfig                     `mapstructure:"token"`
	Payload               auth.PayloadConfig                   `mapstructure:"payload"`
	Status                *auth.StatusConfig                   `mapstructure:"status"`
	UserStatus            auth.UserStatusConfig                `mapstructure:"user_status"`
	Auth                  AuthConfig                           `mapstructure:"auth"`
	AuthSqlConfig         auth.SqlConfig                       `mapstructure:"auth_sql"`
	Password              PasswordConfig                       `mapstructure:"password"`
	SignUp                signup.SignUpConfigWithEmailTemplate `mapstructure:"sign_up"`
	OAuth2                OAuth2Config                         `mapstructure:"oauth2"`
	Mail                  MailConfig                           `mapstructure:"mail"`
	CallBackURL           CallBackURL                          `mapstructure:"callback_url"`
}

type ServerConfig struct {
	Name string `mapstructure:"name"`
	Port int    `mapstructure:"port"`
}

type CallBackURL struct {
	Microsoft string `mapstructure:"microsoft"`
	Amazon    string `mapstructure:"amazon"`
	Twitter   string `mapstructure:"twitter"`
}

type AuthConfig struct {
	Expires  int                 `mapstructure:"expires"`
	Template mail.TemplateConfig `mapstructure:"template"`
	Schema   auth.SchemaConfig   `mapstructure:"schema"`
}

type PasswordTemplateConfig struct {
	ResetTemplate  mail.TemplateConfig `mapstructure:"reset"`
	ChangeTemplate mail.TemplateConfig `mapstructure:"change"`
}

type PasswordConfig struct {
	ResetExpires  int                           `mapstructure:"reset_expires"`
	ChangeExpires int                           `mapstructure:"change_expires"`
	Exp1          string                        `mapstructure:"exp1"`
	Exp2          string                        `mapstructure:"exp2"`
	Exp3          string                        `mapstructure:"exp3"`
	Exp4          string                        `mapstructure:"exp4"`
	Exp5          string                        `mapstructure:"exp5"`
	Exp6          string                        `mapstructure:"exp6"`
	Schema        password.PasswordSchemaConfig `mapstructure:"schema"`
	Template      PasswordTemplateConfig        `mapstructure:"template"`
}

type MailConfig struct {
	Provider       string            `mapstructure:"provider"`
	From           mail.Email        `mapstructure:"from"`
	SendGridAPIkey string            `mapstructure:"send_grid_api_key"`
	Smtp           smtp.DialerConfig `mapstructure:"smtp"`
}

type OAuth2Config struct {
	Services string                    `mapstructure:"services"`
	Schema   oauth2.OAuth2SchemaConfig `mapstructure:"schema"`
}
