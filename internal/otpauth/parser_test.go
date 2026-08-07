package otpauth

import (
	"strings"
	"testing"

	"github.com/G6kco/Prover/internal/domain"
)

func TestParse_Valid(t *testing.T) {
	got, err := Parse("otpauth://totp/MyApp:user@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != domain.TypeTOTP || got.Issuer != "MyApp" ||
		got.Account != "user@gmail.com" || got.Digits != 6 || got.Period != 30 {
		t.Fatalf("bad parse: %+v", got)
	}
}

func TestParse_LabelWithoutIssuer(t *testing.T) {
	got, err := Parse("otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if got.Account != "alice@example.com" || got.Issuer != "" {
		t.Fatalf("bad parse: %+v", got)
	}
}

func TestParse_Rejects(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"wrong scheme":       "https://totp/a?secret=JBSWY3DPEHPK3PXP",
		"unknown type":       "otpauth://motp/a?secret=JBSWY3DPEHPK3PXP",
		"no secret":          "otpauth://totp/a",
		"bad base32":         "otpauth://totp/a?secret=!!!!!!!!!!",
		"digits out of range": "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=20",
		"period zero":        "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0",
		"bad algorithm":      "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
		"hotp no counter":    "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP",
		"too long":           "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&x=" + strings.Repeat("A", MaxURILen),
	}
	for name, uri := range cases {
		if _, err := Parse(uri); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// The counter must survive values above 2^31. The original implementation used
// strconv.ParseInt(s, 10, 8), which caps at 127.
func TestParse_LargeHOTPCounter(t *testing.T) {
	got, err := Parse("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=4294967296")
	if err != nil {
		t.Fatal(err)
	}
	if got.Counter != 4294967296 {
		t.Fatalf("counter truncated: %d", got.Counter)
	}
}

// Secrets must never reach a log line. String() redacts; this test locks that in.
func TestOTPAuth_StringRedacts(t *testing.T) {
	o, _ := Parse("otpauth://totp/MyApp:user@gmail.com?secret=JBSWY3DPEHPK3PXP")
	if strings.Contains(o.String(), "JBSWY3DPEHPK3PXP") {
		t.Fatal("String() leaks the secret")
	}
}

// Run with: go test -fuzz=FuzzParse ./internal/otpauth
// The only property that matters is: never panic on hostile input.
func FuzzParse(f *testing.F) {
	f.Add("otpauth://totp/MyApp:user@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp")
	f.Add("otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP&counter=1")
	f.Add("otpauth://totp/:")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = Parse(s)
	})
}
