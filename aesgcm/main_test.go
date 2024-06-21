package aesgcm

import (
	"testing"

	"github.com/toxyl/flo"
)

func Test_test(t *testing.T) {
	tests := []struct {
		name string
		file string
		text string
		key  string
	}{
		{"test 1", "../test_data/test1.txt", "Hello World!", "myKey123"},
		{"test 2", "../test_data/test2.txt", "Hello World!", "12345678"},
		{"test 3", "../test_data/test3.txt", "Hello World!", "1234567890"},
		{"test 4", "../test_data/test4.txt", "Hello World!", "1111"},
		{"test 5", "../test_data/test.bin", "Hello World!", "1234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, _ := Encrypt(tt.text, tt.key)
			d, _ := Decrypt(e, tt.key)
			if tt.text != d {
				t.Errorf("encrypt/decrypt failed: %v: expected %v, got %v!\n", tt.name, tt.text, d)
			} else {
				t.Logf("encrypt/decrypt succesful: %v (%s - %s)\n", tt.name, d, e)
			}

			raw := flo.File(tt.file).AsString()

			if err := EncryptFile(tt.file, tt.key); err != nil {
				t.Errorf("could not encrypt file: %s\n", err)
			}
			encrypted := flo.File(tt.file).AsString()

			if err := DecryptFile(tt.file, tt.key); err != nil {
				t.Errorf("could not decrypt file: %s\n", err)
			}
			decrypted := flo.File(tt.file).AsString()

			if decrypted != raw {
				t.Errorf("decryption failed, expected %s but got (%s - %s)\n", raw, decrypted, encrypted)
			} else {
				t.Logf("encrypt/decrypt file succesful: %v (%s - %s)\n", tt.name, decrypted, encrypted)
			}
		})
	}
}
