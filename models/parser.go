package models

type ParsedURI struct {
	Type    string
	Issuer  string
	Account string
	Secret  string
	Digits  int64
	Period  int64
	Counter int64
}
