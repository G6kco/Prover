package crypto

import (
	"encoding/base32"
	"strings"
)


func DecodeSecret(s string) ([]byte, error) {
	secret, err := NormalizeSecret(s)
	if err != nil {
		return nil, err
	}

	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return nil, ErrInvalidSecret
	}

	if len(decoded) < MinSecretSize {
		return nil, ErrInvalidSecret
	}

	return decoded, nil
}


func NormalizeSecret(s string) (string, error) {
	secret := strings.ToUpper(s)
	secret = strings.Join(strings.Fields(secret), "")
	secret = strings.TrimRight(secret, "=")

	if secret == "" {
		return "", ErrInvalidSecret
	}

	return secret, nil
}
