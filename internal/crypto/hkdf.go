package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func deriveKey(mk, info []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, mk, nil, info)

	out := make([]byte, KeySize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}

	return out, nil
}

func DeriveEncKey(mk []byte) ([]byte, error) {
	return deriveKey(mk, []byte("prover|enc|v1"))
}

func DeriveAuthKey(mk []byte) ([]byte, error) {
	return deriveKey(mk, []byte("prover|auth|v1"))
}