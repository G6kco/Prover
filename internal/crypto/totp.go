package crypto

import (
	"crypto/subtle"
	"time"
)

type TOTPParams struct {
	Key    []byte
	Digits int
	Period int64
	Alg    Algorithm
	Skew   int
}

func Counter(t time.Time, period int64) uint64 {
	return uint64(t.Unix() / period)
}

func TOTP(p TOTPParams, t time.Time) (string, error) {
	return HOTP(p.Key, Counter(t, p.Period), p.Digits, p.Alg)
}

func VerifyTOTP(p TOTPParams, code string, now time.Time) (bool, uint64, error) {
	for offset := -p.Skew; offset <= p.Skew; offset++{
		window := now.Add(time.Duration(offset) * time.Duration(p.Period) * time.Second)
		want, err := TOTP(p,window)
		if err != nil{
			return false,0, err
		}
		
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1{
			return true, Counter(window, p.Period), nil
		}
	}
	
	return false, 0, nil
}
