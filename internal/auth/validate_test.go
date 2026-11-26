package auth

import "testing"

func TestValidateRegisterOK(t *testing.T) {
	in, errs := ValidateRegister("  Alice  ", "Ali", "User.Name_1", "password-15chars")
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %+v", errs)
	}
	if in.Name != "Alice" || in.Nickname != "Ali" || in.Login != "user.name_1" {
		t.Fatalf("normalized input: %+v", in)
	}
}

func TestValidateRegisterFailures(t *testing.T) {
	_, errs := ValidateRegister("", "x", "ab", "short")
	if len(errs) < 3 {
		t.Fatalf("expected multiple field errors, got %+v", errs)
	}
}

func TestNormalizeLogin(t *testing.T) {
	if got := NormalizeLogin("  AbC_DeF  "); got != "abc_def" {
		t.Fatalf("got %q", got)
	}
}
