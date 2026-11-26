package auth

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	loginPattern    = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	nicknamePattern = regexp.MustCompile(`^[\p{L}\p{N}._\-\s]+$`)
)

// RegisterInput is the validated registration payload.
type RegisterInput struct {
	Name     string
	Nickname string
	Login    string
	Password string
}

// FieldError describes a single validation failure for API responses.
type FieldError struct {
	Field   string
	Message string
}

func (e FieldError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// NormalizeLogin lowercases and trims login for uniqueness checks.
func NormalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

// ValidateRegister validates and normalizes registration fields.
func ValidateRegister(name, nickname, login, password string) (RegisterInput, []FieldError) {
	var errs []FieldError
	out := RegisterInput{}

	out.Name = strings.TrimSpace(name)
	if out.Name == "" {
		errs = append(errs, FieldError{Field: "name", Message: "Имя обязательно"})
	} else if n := utf8.RuneCountInString(out.Name); n < 1 || n > 80 {
		errs = append(errs, FieldError{Field: "name", Message: "Имя должно содержать от 1 до 80 символов"})
	}

	out.Nickname = strings.TrimSpace(nickname)
	if out.Nickname == "" {
		errs = append(errs, FieldError{Field: "nickname", Message: "Никнейм обязателен"})
	} else {
		n := utf8.RuneCountInString(out.Nickname)
		if n < 2 || n > 32 {
			errs = append(errs, FieldError{Field: "nickname", Message: "Никнейм должен содержать от 2 до 32 символов"})
		} else if !nicknamePattern.MatchString(out.Nickname) {
			errs = append(errs, FieldError{Field: "nickname", Message: "Никнейм содержит недопустимые символы"})
		}
	}

	rawLogin := strings.TrimSpace(login)
	if rawLogin == "" {
		errs = append(errs, FieldError{Field: "login", Message: "Логин обязателен"})
	} else {
		n := utf8.RuneCountInString(rawLogin)
		if n < 3 || n > 32 {
			errs = append(errs, FieldError{Field: "login", Message: "Логин должен содержать от 3 до 32 символов"})
		} else if !loginPattern.MatchString(rawLogin) {
			errs = append(errs, FieldError{Field: "login", Message: "Логин может содержать только латинские буквы, цифры, точку, дефис и подчёркивание"})
		} else {
			out.Login = NormalizeLogin(rawLogin)
		}
	}

	// Do not trim password.
	out.Password = password
	if out.Password == "" {
		errs = append(errs, FieldError{Field: "password", Message: "Пароль обязателен"})
	} else {
		n := utf8.RuneCountInString(out.Password)
		if n < 15 {
			errs = append(errs, FieldError{Field: "password", Message: "Пароль должен содержать не менее 15 символов"})
		} else if n > 128 {
			errs = append(errs, FieldError{Field: "password", Message: "Пароль должен содержать не более 128 символов"})
		}
	}

	return out, errs
}

// ValidateLoginCredentials validates login form fields (without existence checks).
func ValidateLoginCredentials(login, password string) (normalizedLogin string, errs []FieldError) {
	rawLogin := strings.TrimSpace(login)
	if rawLogin == "" {
		errs = append(errs, FieldError{Field: "login", Message: "Логин обязателен"})
	} else {
		normalizedLogin = NormalizeLogin(rawLogin)
	}
	if password == "" {
		errs = append(errs, FieldError{Field: "password", Message: "Пароль обязателен"})
	}
	return normalizedLogin, errs
}
