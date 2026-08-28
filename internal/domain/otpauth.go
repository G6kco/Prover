package domain

import (
	"fmt"

	"github.com/G6kco/Prover/internal/crypto"
)

type Type string

const (
	TypeTOTP Type = "totp"
	TypeHOTP Type = "hotp"
)

type OTPAuth struct {
	Type      Type
	Issuer    string
	Account   string
	Secret    []byte
	Digits    int
	Period    int64
	Algorithm crypto.Algorithm
	Counter   uint64
}

func (o OTPAuth) String() string {
	return fmt.Sprintf("OTPAuth{Type:%s, Issuer:%s, Account:%s, Digits:%d, Period:%d, Secret:REDACTED}", o.Type, o.Issuer, o.Account, o.Digits, o.Period)
}
