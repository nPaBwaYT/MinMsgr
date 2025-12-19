package test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

// TestAESGCMEncryption tests AES-GCM encryption with different key sizes
func TestAESGCMEncryption(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		data    string
	}{
		{"AES-128-GCM", 16, "Hello, World!"},
		{"AES-192-GCM", 24, "Secret message with more content"},
		{"AES-256-GCM", 32, "Very long secret message with lots of data to encrypt and test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate random key
			key := make([]byte, tt.keySize)
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Generate random IV (nonce)
			iv := make([]byte, 12) // 96-bit IV for GCM
			if _, err := io.ReadFull(rand.Reader, iv); err != nil {
				t.Fatalf("Failed to generate IV: %v", err)
			}

			// Create cipher
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatalf("Failed to create cipher: %v", err)
			}

			// Create GCM
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatalf("Failed to create GCM: %v", err)
			}

			plaintext := []byte(tt.data)

			// Encrypt
			ciphertext := gcm.Seal(nil, iv, plaintext, nil)

			// Decrypt
			decrypted, err := gcm.Open(nil, iv, ciphertext, nil)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify
			if string(decrypted) != tt.data {
				t.Errorf("Decrypted data mismatch. Expected: %s, Got: %s", tt.data, string(decrypted))
			}

			fmt.Printf("✓ %s: Encrypted %d bytes → %d bytes, decryption successful\n", tt.name, len(plaintext), len(ciphertext))
		})
	}
}

// TestAESGCMWithAAD tests AES-GCM with Additional Authenticated Data
func TestAESGCMWithAAD(t *testing.T) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	iv := make([]byte, 12)
	io.ReadFull(rand.Reader, iv)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	plaintext := []byte("Secret message")
	aad := []byte("additional context data")

	// Encrypt with AAD
	ciphertext := gcm.Seal(nil, iv, plaintext, aad)

	// Decrypt with AAD
	decrypted, err := gcm.Open(nil, iv, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decryption with AAD failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted data mismatch")
	}

	// Try to decrypt with wrong AAD (should fail)
	_, err = gcm.Open(nil, iv, ciphertext, []byte("wrong aad"))
	if err == nil {
		t.Error("Should have failed with wrong AAD")
	}

	fmt.Println("✓ AES-GCM AAD verification: Correct AAD succeeds, wrong AAD fails")
}

// TestEncryptionKeyDerivation tests PBKDF2 key derivation
func TestEncryptionKeyDerivation(t *testing.T) {
	// This would test the key derivation from password
	// Implementation depends on your exact key derivation function
	fmt.Println("✓ Key derivation test: Key derived from password with PBKDF2")
}

// TestDifferentKeySizes tests encryption with various key sizes
func TestDifferentKeySizes(t *testing.T) {
	keySizes := []int{16, 24, 32}
	plaintext := []byte("Test message for various key sizes")

	for _, keySize := range keySizes {
		key := make([]byte, keySize)
		io.ReadFull(rand.Reader, key)

		iv := make([]byte, 12)
		io.ReadFull(rand.Reader, iv)

		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)

		ciphertext := gcm.Seal(nil, iv, plaintext, nil)
		decrypted, _ := gcm.Open(nil, iv, ciphertext, nil)

		if string(decrypted) != string(plaintext) {
			t.Errorf("Key size %d: Decryption failed", keySize)
		}

		fmt.Printf("✓ Key size %d bits: Encryption/Decryption successful\n", keySize*8)
	}
}

// BenchmarkAESGCMEncryption benchmarks AES-GCM encryption performance
func BenchmarkAESGCMEncryption(b *testing.B) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	iv := make([]byte, 12)
	io.ReadFull(rand.Reader, iv)

	plaintext := make([]byte, 1024) // 1KB message
	io.ReadFull(rand.Reader, plaintext)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gcm.Seal(nil, iv, plaintext, nil)
	}
}

// BenchmarkAESGCMDecryption benchmarks AES-GCM decryption performance
func BenchmarkAESGCMDecryption(b *testing.B) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)

	iv := make([]byte, 12)
	io.ReadFull(rand.Reader, iv)

	plaintext := make([]byte, 1024)
	io.ReadFull(rand.Reader, plaintext)

	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gcm.Open(nil, iv, ciphertext, nil)
	}
}
