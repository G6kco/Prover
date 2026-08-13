package crypto

import (
	"testing"
	"time"
)

// RFC 4226 Appendix D — HOTP test vectors.
// Secret: ASCII "12345678901234567890", 6 digits, SHA-1.
func TestHOTP_RFC4226(t *testing.T) {
	key := []byte("12345678901234567890")
	want := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for c, exp := range want {
		got, err := HOTP(key, uint64(c), 6, AlgSHA1)
		if err != nil {
			t.Fatalf("counter %d: %v", c, err)
		}
		if got != exp {
			t.Errorf("counter %d: got %s want %s", c, got, exp)
		}
	}
}

// RFC 6238 Appendix B — TOTP test vectors, 8 digits.
//
// Note the seeds differ per algorithm: the RFC's SHA-256 and SHA-512 vectors
// use the ASCII string repeated and truncated to the hash block-ish length, not
// the same 20-byte seed. Getting this wrong is the usual reason people think
// their SHA-256 implementation is broken.
func TestTOTP_RFC6238(t *testing.T) {
	seed1 := []byte("12345678901234567890")                                               // 20 bytes
	seed256 := []byte("12345678901234567890123456789012")                                 // 32 bytes
	seed512 := []byte("1234567890123456789012345678901234567890123456789012345678901234") // 64 bytes

	cases := []struct {
		unix                 int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}

	for _, c := range cases {
		ts := time.Unix(c.unix, 0).UTC()
		for _, v := range []struct {
			alg  Algorithm
			key  []byte
			want string
		}{
			{AlgSHA1, seed1, c.sha1},
			{AlgSHA256, seed256, c.sha256},
			{AlgSHA512, seed512, c.sha512},
		} {
			got, err := TOTP(TOTPParams{
				Key: v.key, Digits: 8, Period: DefaultPeriod, Alg: v.alg,
			}, ts)
			if err != nil {
				t.Fatalf("t=%d alg=%s: %v", c.unix, v.alg, err)
			}
			if got != v.want {
				t.Errorf("t=%d alg=%s: got %s want %s", c.unix, v.alg, got, v.want)
			}
		}
	}
}

func TestVerifyTOTP_Window(t *testing.T) {
	key := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0)
	p := TOTPParams{Key: key, Digits: 6, Period: 30, Alg: AlgSHA1, Skew: 1}

	code, err := TOTP(p, now.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ok, counter, err := VerifyTOTP(p, code, now)
	if err != nil || !ok {
		t.Fatalf("previous step should be accepted with skew=1: ok=%v err=%v", ok, err)
	}
	if counter != Counter(now, 30)-1 {
		t.Errorf("wrong matched counter: %d", counter)
	}

	// Two steps out must be rejected with skew=1.
	old, _ := TOTP(p, now.Add(-90*time.Second))
	if ok, _, _ := VerifyTOTP(p, old, now); ok {
		t.Error("code two steps old should be rejected")
	}
}

func TestDecodeSecret(t *testing.T) {
	// Canonical example from the Google Authenticator Key URI spec.
	if _, err := DecodeSecret("JBSWY3DPEHPK3PXP"); err != nil {
		t.Errorf("valid secret rejected: %v", err)
	}
	// Lowercase, spaced, and padded forms all appear in the wild.
	if _, err := DecodeSecret("jbsw y3dp ehpk 3pxp"); err != nil {
		t.Errorf("spaced/lowercase secret rejected: %v", err)
	}
	for _, bad := range []string{"", "!!!!", "AAAA", "1234567890"} {
		if _, err := DecodeSecret(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

func TestUnknownAlgorithmRejected(t *testing.T) {
	if _, err := HOTP([]byte("12345678901234567890"), 0, 6, "MD5"); err == nil {
		t.Error("unknown algorithm must be rejected, not silently defaulted")
	}
}
