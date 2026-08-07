package crypto

import "errors"

type Algorithm string

const (
	KeySize                 = 32
	NonceSize               = 24
	SaltSize                = 16
	// MinSecretSize is the minimum decoded HOTP/TOTP secret length, in
	// bytes (80 bits, the floor RFC 4226 recommends).
	MinSecretSize           = 10
	DefaultPeriod           = 30
	AlgSHA1       Algorithm = "SHA1"
	AlgSHA256     Algorithm = "SHA256"
	AlgSHA512     Algorithm = "SHA512"
)

var (
	// ErrOpen is returned when AEAD decryption fails: the ciphertext was tampered with, the key is wrong, or the AAD does not match what the envelope was sealed under.
	ErrOpen = errors.New("crypto: open failed: authentication error")

	// ErrInvalidAlgorithm is returned when an Algorithm value is not one of the supported HOTP/TOTP hash algorithms.
	ErrInvalidAlgorithm = errors.New("crypto: unsupported algorithm")

	// ErrInvalidSecret is returned when a TOTP secret cannot be decoded as base32.
	ErrInvalidSecret = errors.New("crypto: invalid secret")

	// ErrInvalidKeySize is returned when a key, nonce, or salt size argument is invalid (non-positive, or not the size an algorithm requires).
	ErrInvalidKeySize = errors.New("crypto: invalid key size")

	// ErrRandomRead is returned when the OS entropy source fails to produce random bytes.
	ErrRandomRead = errors.New("crypto: failed to read random bytes")
)

type Envelope struct{ Nonce, Ciphertext []byte }
