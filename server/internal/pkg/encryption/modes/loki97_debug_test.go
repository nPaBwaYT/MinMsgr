package modes

import (
	"bytes"
	"encoding/hex"
	"testing"

	"MinMsgr/server/internal/pkg/encryption"
)

// TestLOKI97DebugDirectBlock - Debug LOKI97 block encryption
func TestLOKI97DebugDirectBlock(t *testing.T) {
	cipher, err := encryption.NewLOKI97(testKey128)
	if err != nil {
		t.Fatalf("Failed to create LOKI97: %v", err)
	}

	plaintext := []byte("12345678")
	t.Logf("Plaintext:  %s (%s)", plaintext, hex.EncodeToString(plaintext))

	encrypted, err := cipher.Encrypt(testKey128, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	t.Logf("Encrypted:  %s (%s)", encrypted, hex.EncodeToString(encrypted))

	decrypted, err := cipher.Decrypt(testKey128, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	t.Logf("Decrypted:  %s (%s)", decrypted, hex.EncodeToString(decrypted))

	if bytes.Equal(plaintext, decrypted) {
		t.Logf("✅ Match!")
	} else {
		t.Logf("❌ NO MATCH")

		// Check byte by byte
		for i, b := range plaintext {
			if i < len(decrypted) {
				if b == decrypted[i] {
					t.Logf("  [%d] ✅ %02x == %02x", i, b, decrypted[i])
				} else {
					t.Logf("  [%d] ❌ %02x != %02x", i, b, decrypted[i])
				}
			}
		}
	}
}
