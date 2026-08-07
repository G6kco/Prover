package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

func HOTP(key []byte, counter uint64, digits int, alg Algorithm) (string, error) {
	var h func() hash.Hash

	switch alg {
	case AlgSHA1:
		h = sha1.New
	case AlgSHA256:
		h = sha256.New
	case AlgSHA512:
		h = sha512.New
	default:
		{
			return "", ErrInvalidAlgorithm
		}
	}

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(h, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0F
	binCode := (uint32(sum[offset])&0x7F)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(math.Pow10(digits))
	code := binCode % mod
	
	return fmt.Sprintf("%0*d",digits,code), nil
}
