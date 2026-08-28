package otpauth

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/G6kco/Prover/internal/crypto"
	"github.com/G6kco/Prover/internal/domain"
)

const MaxURILen = 3000

func Parse(URI string) (*domain.OTPAuth, error) {
	if len(URI) > MaxURILen {
		return nil, fmt.Errorf("uri length exceeded: len=%d", len(URI))
	}

	if URI == "" {
		return nil, fmt.Errorf("empty uri")
	}

	u, err := url.Parse(URI)

	if err != nil {
		return nil, err
	} else if u.Scheme != "otpauth" {
		return nil, fmt.Errorf("invalid scheme: %q", u.Scheme)
	}

	otpAuthType := domain.Type(u.Host)
	if otpAuthType != domain.TypeTOTP && otpAuthType != domain.TypeHOTP {
		return nil, fmt.Errorf("unknown type: %q", u.Host)
	}

	Label := strings.TrimPrefix(u.Path, "/")
	parts := strings.SplitN(Label, ":", 2)

	var issuer, account string

	if len(parts) == 2 {
		issuer, account = parts[0], parts[1]
	} else {
		issuer, account = "", parts[0]
	}

	q := u.Query()
	secretParam := q.Get("secret")
	if secretParam == "" {
		return nil, fmt.Errorf("invalid secret")
	}

	secret, err := crypto.DecodeSecret(secretParam)
	if err != nil {
		return nil, err
	}

	if q.Get("issuer") != "" {
		issuer = q.Get("issuer")
	}

	var digits int
	if q.Get("digits") == "" {
		digits = 6
	} else {
		res, err := strconv.Atoi(q.Get("digits"))
		if err != nil {
			return nil, err
		}

		if 6 <= res && res <= 8 {
			digits = res
		} else {
			return nil, fmt.Errorf("digits out of range")
		}
	}

	var period int64
	if q.Get("period") == "" {
		period = crypto.DefaultPeriod
	} else {
		p, err := strconv.ParseInt(q.Get("period"), 10, 64)
		if err != nil {
			return nil, err
		}

		if p > 0 {
			period = p
		} else {
			return nil, fmt.Errorf("period is invalid")
		}
	}

	var algorithm crypto.Algorithm
	alg := q.Get("algorithm")

	if alg == "" {
		algorithm = crypto.AlgSHA1
	} else {
		switch alg {
		case string(crypto.AlgSHA1):
			algorithm = crypto.AlgSHA1
		case string(crypto.AlgSHA256):
			algorithm = crypto.AlgSHA256
		case string(crypto.AlgSHA512):
			algorithm = crypto.AlgSHA512
		default:
			return nil, fmt.Errorf("invalid algorithm: %q", alg)
		}
	}

	var counter uint64 = 0
	if otpAuthType == domain.TypeHOTP {
		if q.Get("counter") == "" {
			return nil, fmt.Errorf("HOTP requires counter")
		}

		c, err := strconv.ParseUint(q.Get("counter"), 10, 64)
		if err != nil {
			return nil, err
		}
		counter = c

	}

	otpAuth := &domain.OTPAuth{
		Type:      otpAuthType,
		Issuer:    issuer,
		Account:   account,
		Secret:    secret,
		Digits:    digits,
		Period:    period,
		Algorithm: algorithm,
		Counter:   counter,
	}

	return otpAuth, nil
}
