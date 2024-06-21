// Package aesgcm provides encryption and decryption functionalities using AES-GCM mode.
// It supports encryption and decryption of data and files using a provided key.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/toxyl/errors"
	"github.com/toxyl/flo"
	"github.com/toxyl/keys"
)

// keyCipher represents a structure holding the AES key for encryption and decryption.
type keyCipher struct {
	key []byte
}

// newKeyCipher creates a new keyCipher instance initialized with a scrambled key.
// It returns an error if key scrambling fails.
func newKeyCipher(key string) (*keyCipher, error) {
	k, err := keys.WeakKeyScrambler(key)
	if err != nil {
		return nil, err
	}
	return &keyCipher{key: []byte(k)}, nil
}

// encrypt encrypts the provided data using AES-GCM encryption.
// It returns the encrypted ciphertext along with any error encountered.
func (c *keyCipher) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return aesGCM.Seal(nonce, nonce, data, nil), nil
}

// decrypt decrypts the provided AES-GCM encrypted data.
// It returns the decrypted plaintext along with any error encountered.
func (c *keyCipher) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Encrypt encrypts the given plaintext using AES-GCM encryption with the provided key.
// It returns the base64-encoded encrypted ciphertext and any error encountered.
//
// The provided key undergoes scrambling using keys.WeakKeyScrambler to ensure it is 32 bytes long,
// which is the maximum allowed length for AES-GCM encryption. This process enhances security by converting
// potentially weak passwords into a stronger key format. The scrambled key is stored internally and
// used for encryption and decryption operations within this package.
//
// Note: The input key is not directly usable with other AES-GCM implementations or tools,
// as it undergoes specific scrambling tailored for this package's usage.
func Encrypt(plaintext, key string) (string, error) {
	cipher, err := newKeyCipher(key)
	if err != nil {
		return "", err
	}
	encrypted, err := cipher.encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt decrypts the given base64-encoded encrypted text using AES-GCM decryption with the provided key.
// It returns the decrypted plaintext and any error encountered.
func Decrypt(encryptedText, key string) (string, error) {
	cipher, err := newKeyCipher(key)
	if err != nil {
		return "", err
	}
	encryptedData, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}
	decrypted, err := cipher.decrypt(encryptedData)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// EncryptFile encrypts the file located at 'path' using AES-GCM encryption with the provided key.
// It returns an error if the file doesn't exist or if any encryption operation fails.
//
// The provided key undergoes scrambling using keys.WeakKeyScrambler to ensure it is 32 bytes long,
// which is the maximum allowed length for AES-GCM encryption. This process enhances security by converting
// potentially weak passwords into a stronger key format. The scrambled key is stored internally and
// used for encryption and decryption operations within this package.
//
// Note: The input key is not directly usable with other AES-GCM implementations or tools,
// as it undergoes specific scrambling tailored for this package's usage.
func EncryptFile(path, key string) error {
	f := flo.File(path)
	if !f.Exists() {
		return errors.Newf("can't encrypt, file '%s' does not exist", f.Path())
	}
	cipher, err := newKeyCipher(key)
	if err != nil {
		return err
	}
	encrypted, err := cipher.encrypt(f.AsBytes())
	if err != nil {
		return err
	}
	if err := f.StoreBytes(encrypted); err != nil {
		return err
	}
	return nil
}

// DecryptFile decrypts the file located at 'path' using AES-GCM decryption with the provided key.
// It returns an error if the file doesn't exist or if any decryption operation fails.
func DecryptFile(path, key string) error {
	f := flo.File(path)
	if !f.Exists() {
		return errors.Newf("can't decrypt, file '%s' does not exist", f.Path())
	}
	cipher, err := newKeyCipher(key)
	if err != nil {
		return err
	}
	decrypted, err := cipher.decrypt(f.AsBytes())
	if err != nil {
		return err
	}
	if err := f.StoreBytes(decrypted); err != nil {
		return err
	}
	return nil
}
