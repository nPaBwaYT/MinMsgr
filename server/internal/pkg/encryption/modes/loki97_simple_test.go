package modes

import (
	"bytes"
	"testing"

	"MinMsgr/server/internal/pkg/encryption"
	"MinMsgr/server/internal/pkg/encryption/padding"
)

// TestLOKI97CBCSimple - Simple test to verify LOKI97 + CBC + PKCS7 works
func TestLOKI97CBCSimple(t *testing.T) {
	// Create LOKI97 cipher
	cipher, err := encryption.NewLOKI97(testKey128)
	if err != nil {
		t.Fatalf("Failed to create LOKI97: %v", err)
	}

	// Test message (arbitrary length)
	plaintext := []byte("Hello, World! This is LOKI97 test.")

	// Get PKCS7 padder
	padder := padding.GetPadder("PKCS7")

	// Pad the plaintext to LOKI97 block size (8 bytes)
	paddedPlaintext := padder.Pad(plaintext, cipher.BlockSize())

	t.Logf("Plaintext: %d bytes", len(plaintext))
	t.Logf("Padded: %d bytes (should be multiple of %d)", len(paddedPlaintext), cipher.BlockSize())

	if len(paddedPlaintext)%cipher.BlockSize() != 0 {
		t.Fatalf("Padded plaintext not multiple of block size")
	}

	// Get CBC mode
	mode := &CBCMode{}

	// Encrypt
	ciphertext, err := mode.Encrypt(cipher, testKey128, paddedPlaintext, testIV8)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	t.Logf("Ciphertext: %d bytes", len(ciphertext))

	// Decrypt
	decrypted, err := mode.Decrypt(cipher, testKey128, ciphertext, testIV8)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	t.Logf("Decrypted (padded): %d bytes", len(decrypted))

	// Unpad
	unpadded, err := padder.Unpad(decrypted)
	if err != nil {
		t.Fatalf("Unpadding failed: %v", err)
	}

	t.Logf("Unpadded: %d bytes", len(unpadded))

	// Compare
	if !bytes.Equal(plaintext, unpadded) {
		t.Fatalf("Mismatch!\nExpected: %v\nGot: %v", plaintext, unpadded)
	}

	t.Logf("✅ LOKI97 + CBC + PKCS7: SUCCESS")
}

// TestLOKI97ECBSimple - Simple test to verify LOKI97 + ECB + PKCS7 works
func TestLOKI97ECBSimple(t *testing.T) {
	cipher, err := encryption.NewLOKI97(testKey128)
	if err != nil {
		t.Fatalf("Failed to create LOKI97: %v", err)
	}

	plaintext := []byte("Test message for ECB mode")
	padder := padding.GetPadder("PKCS7")
	paddedPlaintext := padder.Pad(plaintext, cipher.BlockSize())

	t.Logf("Plaintext: %d bytes", len(plaintext))
	t.Logf("Padded: %d bytes (should be multiple of %d)", len(paddedPlaintext), cipher.BlockSize())

	if len(paddedPlaintext)%cipher.BlockSize() != 0 {
		t.Fatalf("Padded plaintext not multiple of block size")
	}

	mode := &ECBMode{}

	// Encrypt
	ciphertext, err := mode.Encrypt(cipher, testKey128, paddedPlaintext, nil)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt
	decrypted, err := mode.Decrypt(cipher, testKey128, ciphertext, nil)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Unpad
	unpadded, err := padder.Unpad(decrypted)
	if err != nil {
		t.Fatalf("Unpadding failed: %v", err)
	}

	// Compare
	if !bytes.Equal(plaintext, unpadded) {
		t.Fatalf("Mismatch!\nExpected: %v\nGot: %v", plaintext, unpadded)
	}

	t.Logf("✅ LOKI97 + ECB + PKCS7: SUCCESS")
}

// TestLOKI97DirectEncrypt - Test LOKI97 Encrypt/Decrypt directly
func TestLOKI97DirectEncrypt(t *testing.T) {
	cipher, err := encryption.NewLOKI97(testKey128)
	if err != nil {
		t.Fatalf("Failed to create LOKI97: %v", err)
	}

	// Must be exactly 8 bytes
	plaintext := []byte("12345678")

	encrypted, err := cipher.Encrypt(testKey128, plaintext)
	if err != nil {
		t.Fatalf("Direct encrypt failed: %v", err)
	}

	decrypted, err := cipher.Decrypt(testKey128, encrypted)
	if err != nil {
		t.Fatalf("Direct decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Direct encrypt/decrypt failed")
	}

	t.Logf("✅ LOKI97 Direct Encrypt/Decrypt: SUCCESS")
}
