package crypto

const (
	PurposePassword = "password"
	PurposeRecovery = "recovery"
)

func NewVaultKey() ([]byte, error) {
	return Random(KeySize)
}

func vaultAAD(userID, purpose string) []byte {
	return []byte(userID + "|" + purpose)
}

func WrapKey(kek, vk []byte, userID, purpose string) (Envelope, error) {
	return Seal(kek, vk, vaultAAD(userID, purpose))
}

func UnwrapKey(kek []byte, env Envelope, userID, purpose string) ([]byte, error) {
	return Open(kek, env, vaultAAD(userID, purpose))
}
