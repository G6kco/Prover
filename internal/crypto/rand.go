package crypto

import "crypto/rand"

func Random(n int) ([]byte, error) {
	if n <= 0 {
		return nil, ErrInvalidKeySize
	}

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, ErrRandomRead
	}

	return b, nil
}

func NewSalt() ([]byte, error) {
	return Random(SaltSize)
}
