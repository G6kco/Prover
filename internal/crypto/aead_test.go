package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpen_RoundTrip(t *testing.T) {
	key, _ := Random(KeySize)
	pt := []byte(`{"issuer":"GitHub","secret":"JBSWY3DPEHPK3PXP"}`)
	aad := ItemAAD("user1", "item1", 1)

	env, err := Seal(key, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Nonce) != NonceSize {
		t.Fatalf("nonce size %d, want %d", len(env.Nonce), NonceSize)
	}
	if bytes.Contains(env.Ciphertext, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatal("plaintext leaked into ciphertext")
	}

	got, err := Open(key, env, aad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip failed: %v", err)
	}
}

// The three attacks the AAD exists to stop.
func TestOpen_AADBinding(t *testing.T) {
	key, _ := Random(KeySize)
	pt := []byte("secret")
	env, _ := Seal(key, pt, ItemAAD("alice", "item1", 1))

	t.Run("swap to another user", func(t *testing.T) {
		if _, err := Open(key, env, ItemAAD("bob", "item1", 1)); !errors.Is(err, ErrOpen) {
			t.Error("ciphertext moved between users must fail authentication")
		}
	})
	t.Run("swap to another item", func(t *testing.T) {
		if _, err := Open(key, env, ItemAAD("alice", "item2", 1)); !errors.Is(err, ErrOpen) {
			t.Error("ciphertext moved between items must fail authentication")
		}
	})
	t.Run("version rollback", func(t *testing.T) {
		if _, err := Open(key, env, ItemAAD("alice", "item1", 2)); !errors.Is(err, ErrOpen) {
			t.Error("version mismatch must fail authentication")
		}
	})
}

func TestOpen_Tampering(t *testing.T) {
	key, _ := Random(KeySize)
	aad := ItemAAD("u", "i", 1)
	env, _ := Seal(key, []byte("secret"), aad)

	env.Ciphertext[0] ^= 0x01 // flip one bit
	if _, err := Open(key, env, aad); !errors.Is(err, ErrOpen) {
		t.Error("bit flip must be detected by the Poly1305 tag")
	}
}

func TestSeal_NonceIsFresh(t *testing.T) {
	key, _ := Random(KeySize)
	aad := ItemAAD("u", "i", 1)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		env, _ := Seal(key, []byte("same plaintext"), aad)
		k := string(env.Nonce)
		if seen[k] {
			t.Fatal("nonce reused")
		}
		seen[k] = true
	}
}

func TestWrapUnwrapVaultKey(t *testing.T) {
	kek, _ := Random(KeySize)
	vk, _ := NewVaultKey()

	env, err := WrapKey(kek, vk, "alice", PurposePassword)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapKey(kek, env, "alice", PurposePassword)
	if err != nil || !bytes.Equal(got, vk) {
		t.Fatalf("unwrap failed: %v", err)
	}
	// A password-wrapped key must not open under the recovery purpose.
	if _, err := UnwrapKey(kek, env, "alice", PurposeRecovery); !errors.Is(err, ErrOpen) {
		t.Error("purpose must be bound into the AAD")
	}
}

// This is the property the whole zero-knowledge claim rests on: the server
// holds the auth key, and the auth key tells it nothing about the enc key.
func TestKeySeparation(t *testing.T) {
	salt, _ := NewSalt()
	mk, err := DeriveMasterKey([]byte("correct horse battery staple"), salt, DefaultArgon2Params())
	if err != nil {
		t.Fatal(err)
	}
	ak, _ := DeriveAuthKey(mk)
	ek, _ := DeriveEncKey(mk)

	if bytes.Equal(ak, ek) {
		t.Fatal("auth key and enc key must be independent")
	}
	if len(ak) != KeySize || len(ek) != KeySize {
		t.Fatal("subkeys must be 32 bytes")
	}

	// Deterministic: the same password + salt must reproduce both keys, or no
	// user could ever log in from a second device.
	mk2, _ := DeriveMasterKey([]byte("correct horse battery staple"), salt, DefaultArgon2Params())
	ak2, _ := DeriveAuthKey(mk2)
	if !bytes.Equal(ak, ak2) {
		t.Fatal("derivation must be deterministic")
	}
}

func TestVerifyAuthKey(t *testing.T) {
	p := DefaultArgon2Params()
	salt, _ := NewSalt()
	ak, _ := Random(KeySize)

	stored, err := HashAuthKey(ak, salt, p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(stored, ak) {
		t.Fatal("stored value must not be the auth key itself")
	}
	if ok, _ := VerifyAuthKey(ak, salt, stored, p); !ok {
		t.Fatal("correct auth key rejected")
	}
	wrong, _ := Random(KeySize)
	if ok, _ := VerifyAuthKey(wrong, salt, stored, p); ok {
		t.Fatal("wrong auth key accepted")
	}
}
