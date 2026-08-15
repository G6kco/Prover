package crypto

import (
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
)

func ItemAAD(userID, itemID string, version int) []byte {
	return []byte(userID + "|" + itemID + "|" + strconv.Itoa(version))
}

func Seal(key, plainText, aad []byte) (Envelope, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Envelope{}, err
	}

	nounce, err := Random(NonceSize)
	if err != nil {
		return Envelope{}, err
	}

	ct := aead.Seal(nil, nounce, plainText, aad)
	return Envelope{Nonce: nounce, Ciphertext: ct}, nil
}

func Open(key []byte, env Envelope, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	
	pt, err := aead.Open(nil, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		return nil, ErrOpen
	}
	
	return pt, nil	
}
