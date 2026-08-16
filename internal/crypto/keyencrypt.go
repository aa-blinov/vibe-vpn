package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// Key encryption parameters (standard primitives only).
const (
	keySaltLen    = 16
	keyNonceLen   = 12
	scryptN       = 1 << 15
	scryptR       = 8
	scryptP       = 1
	keyBlobPrefix = "v1:"
)

// EncryptKey derives a key from the passphrase with scrypt and seals the
// 32-byte private key with ChaCha20-Poly1305. The returned blob is safe to
// store in a config file.
func EncryptKey(priv []byte, passphrase string) (string, error) {
	if len(priv) != 32 {
		return "", errors.New("crypto: private key must be 32 bytes")
	}
	if passphrase == "" {
		return "", errors.New("crypto: passphrase must not be empty")
	}
	salt := make([]byte, keySaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, keyNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := aead.Seal(nil, nonce, priv, nil)

	blob := keyBlobPrefix + base64.RawStdEncoding.EncodeToString(salt) + ":" +
		base64.RawStdEncoding.EncodeToString(nonce) + ":" +
		base64.RawStdEncoding.EncodeToString(ct)
	return blob, nil
}

// DecryptKey opens a blob produced by EncryptKey using the passphrase.
func DecryptKey(blob, passphrase string) ([]byte, error) {
	if !strings.HasPrefix(blob, keyBlobPrefix) {
		return nil, errors.New("crypto: not an encrypted key blob")
	}
	parts := strings.Split(strings.TrimPrefix(blob, keyBlobPrefix), ":")
	if len(parts) != 3 {
		return nil, errors.New("crypto: malformed encrypted key blob")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil || len(salt) != keySaltLen {
		return nil, errors.New("crypto: malformed key salt")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil || len(nonce) != keyNonceLen {
		return nil, errors.New("crypto: malformed key nonce")
	}
	ct, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(ct) < 16 {
		return nil, errors.New("crypto: malformed key ciphertext")
	}
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	priv, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: wrong passphrase or corrupted key: %w", err)
	}
	if len(priv) != 32 {
		return nil, errors.New("crypto: decrypted key is invalid")
	}
	return priv, nil
}
