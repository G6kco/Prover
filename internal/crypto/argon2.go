package crypto

import (
	"crypto/subtle"

	"golang.org/x/crypto/argon2"
)

type Argon2Params struct {
	Memory, Time uint32
	Threads      uint8
	KeyLen       uint32
}

func DefaultArgon2Params() Argon2Params {
	return Argon2Params{Memory: 64 * 1024, Time: 3, Threads: 4, KeyLen: 32}
}

func DeriveMasterKey(password, salt []byte, p Argon2Params) ([]byte, error) {
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Threads, p.KeyLen), nil
}

func HashAuthKey(ak, salt []byte, p Argon2Params) ([]byte, error) {
	return DeriveMasterKey(ak, salt, p)
}

func VerifyAuthKey(ak, salt, stored []byte, p Argon2Params) (bool, error) {
	computed, err := HashAuthKey(ak, salt, p)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(computed, stored) == 1, nil
}
