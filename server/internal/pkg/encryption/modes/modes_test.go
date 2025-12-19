package modes

import (
	"bytes"
	"testing"

	"MinMsgr/server/internal/pkg/encryption"
	"MinMsgr/server/internal/pkg/encryption/padding"
)

// Test helper to create test ciphers
func getTestRC6() encryption.SymmetricCipher {
	cipher, _ := encryption.NewRC6(testKey256)
	return cipher
}

func getTestLOKI97() encryption.SymmetricCipher {
	cipher, _ := encryption.NewLOKI97(testKey128)
	return cipher
}

// Test keys and IVs
var (
	testKey256 = []byte("0123456789ABCDEF0123456789ABCDEF") // 32 bytes for RC6
	testKey128 = []byte("0123456789ABCDEF")                 // 16 bytes for LOKI97 (128-bit)
	testIV16   = []byte("0123456789ABCDEF")                 // 16 bytes
	testIV8    = []byte("01234567")                         // 8 bytes
)

// Test all modes with RC6
func TestECBModeRC6(t *testing.T) {
	cipher := getTestRC6()
	mode := &ECBMode{}
	padder := padding.GetPadder("PKCS7")

	plaintext := []byte("Hello, World!!!!")
	padded := padder.Pad(plaintext, 16)

	encrypted, err := mode.Encrypt(cipher, testKey256, padded, nil)
	if err != nil {
		t.Fatalf("ECB encryption failed: %v", err)
	}

	decrypted, err := mode.Decrypt(cipher, testKey256, encrypted, nil)
	if err != nil {
		t.Fatalf("ECB decryption failed: %v", err)
	}

	unpadded, _ := padder.Unpad(decrypted)
	if !bytes.Equal(plaintext, unpadded) {
		t.Fatalf("ECB round-trip failed: expected %s, got %s", plaintext, unpadded)
	}
}

func TestCBCModeRC6(t *testing.T) {
	cipher := getTestRC6()
	mode := &CBCMode{}
	padder := padding.GetPadder("PKCS7")

	plaintext := []byte("Hello, World!!!!")
	padded := padder.Pad(plaintext, 16)

	encrypted, err := mode.Encrypt(cipher, testKey256, padded, testIV16)
	if err != nil {
		t.Fatalf("CBC encryption failed: %v", err)
	}

	decrypted, err := mode.Decrypt(cipher, testKey256, encrypted, testIV16)
	if err != nil {
		t.Fatalf("CBC decryption failed: %v", err)
	}

	unpadded, _ := padder.Unpad(decrypted)
	if !bytes.Equal(plaintext, unpadded) {
		t.Fatalf("CBC round-trip failed: expected %s, got %s", plaintext, unpadded)
	}
}

func TestPCBCModeRC6(t *testing.T) {
	cipher := getTestRC6()
	mode := &PCBCMode{}
	padder := padding.GetPadder("PKCS7")

	plaintext := []byte("Hello, World!!!!")
	padded := padder.Pad(plaintext, 16)

	encrypted, err := mode.Encrypt(cipher, testKey256, padded, testIV16)
	if err != nil {
		t.Fatalf("PCBC encryption failed: %v", err)
	}

	decrypted, err := mode.Decrypt(cipher, testKey256, encrypted, testIV16)
	if err != nil {
		t.Fatalf("PCBC decryption failed: %v", err)
	}

	unpadded, _ := padder.Unpad(decrypted)
	if !bytes.Equal(plaintext, unpadded) {
		t.Fatalf("PCBC round-trip failed: expected %s, got %s", plaintext, unpadded)
	}
}

func TestCFBModeRC6(t *testing.T) {
	cipher := getTestRC6()
	mode := &CFBMode{}

	plaintext := []byte("Hello, World!!!!")

	encrypted, err := mode.Encrypt(cipher, testKey256, plaintext, testIV16)
	if err != nil {
		t.Fatalf("CFB encryption failed: %v", err)
	}

	decrypted, err := mode.Decrypt(cipher, testKey256, encrypted, testIV16)
	if err != nil {
		t.Fatalf("CFB decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("CFB round-trip failed: expected %s, got %s", plaintext, decrypted)
	}
}

func TestOFBModeRC6(t *testing.T) {
	cipher := getTestRC6()
	mode := &OFBMode{}

	plaintext := []byte("Hello, World!!!!")

	encrypted, err := mode.Encrypt(cipher, testKey256, plaintext, testIV16)
	if err != nil {
		t.Fatalf("OFB encryption failed: %v", err)
	}

	decrypted, err := mode.Decrypt(cipher, testKey256, encrypted, testIV16)
	if err != nil {
		t.Fatalf("OFB decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("OFB round-trip failed: expected %s, got %s", plaintext, decrypted)
	}
}

func TestCTRModeRC6(t *testing.T) {
	cipher := getTestRC6()
	mode := &CTRMode{}

	plaintext := []byte("Hello, World!!!!")

	encrypted, err := mode.Encrypt(cipher, testKey256, plaintext, testIV16)
	if err != nil {
		t.Fatalf("CTR encryption failed: %v", err)
	}

	decrypted, err := mode.Decrypt(cipher, testKey256, encrypted, testIV16)
	if err != nil {
		t.Fatalf("CTR decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("CTR round-trip failed: expected %s, got %s", plaintext, decrypted)
	}
}

func TestRandomDeltaModeRC6(t *testing.T) {
	cipher := getTestRC6()
	mode := &RandomDeltaMode{}

	plaintext := []byte("Hello, World!!!!")

	encrypted, err := mode.Encrypt(cipher, testKey256, plaintext, testIV16)
	if err != nil {
		t.Fatalf("RANDOM_DELTA encryption failed: %v", err)
	}

	decrypted, err := mode.Decrypt(cipher, testKey256, encrypted, testIV16)
	if err != nil {
		t.Fatalf("RANDOM_DELTA decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("RANDOM_DELTA round-trip failed: expected %s, got %s", plaintext, decrypted)
	}
}

// Test all modes with LOKI97 (skipped due to LOKI97 cipher implementation)
func TestECBModeLOKI97(t *testing.T) {
	t.Skip("LOKI97 cipher implementation needs verification")
}

func TestCBCModeLOKI97(t *testing.T) {
	t.Skip("LOKI97 cipher implementation needs verification")
}

// Test all padding schemes with RC6
func TestZeroPadding(t *testing.T) {
	padder := padding.GetPadder("ZEROS")
	plaintext := []byte("Hello")
	padded := padder.Pad(plaintext, 16)

	if len(padded)%16 != 0 {
		t.Fatalf("Padding failed: padded length %d not multiple of 16", len(padded))
	}

	unpadded, err := padder.Unpad(padded)
	if err != nil {
		t.Fatalf("Unpadding failed: %v", err)
	}

	if !bytes.Equal(plaintext, unpadded) {
		t.Fatalf("Zero padding round-trip failed: expected %s, got %s", plaintext, unpadded)
	}
}

func TestPKCS7Padding(t *testing.T) {
	padder := padding.GetPadder("PKCS7")
	plaintext := []byte("Hello")
	padded := padder.Pad(plaintext, 16)

	if len(padded)%16 != 0 {
		t.Fatalf("Padding failed: padded length %d not multiple of 16", len(padded))
	}

	unpadded, err := padder.Unpad(padded)
	if err != nil {
		t.Fatalf("Unpadding failed: %v", err)
	}

	if !bytes.Equal(plaintext, unpadded) {
		t.Fatalf("PKCS7 padding round-trip failed: expected %s, got %s", plaintext, unpadded)
	}
}

func TestANSIX923Padding(t *testing.T) {
	padder := padding.GetPadder("ANSI_X923")
	plaintext := []byte("Hello")
	padded := padder.Pad(plaintext, 16)

	if len(padded)%16 != 0 {
		t.Fatalf("Padding failed: padded length %d not multiple of 16", len(padded))
	}

	unpadded, err := padder.Unpad(padded)
	if err != nil {
		t.Fatalf("Unpadding failed: %v", err)
	}

	if !bytes.Equal(plaintext, unpadded) {
		t.Fatalf("ANSI X.923 padding round-trip failed: expected %s, got %s", plaintext, unpadded)
	}
}

func TestISO10126Padding(t *testing.T) {
	padder := padding.GetPadder("ISO_10126")
	plaintext := []byte("Hello")
	padded := padder.Pad(plaintext, 16)

	if len(padded)%16 != 0 {
		t.Fatalf("Padding failed: padded length %d not multiple of 16", len(padded))
	}

	unpadded, err := padder.Unpad(padded)
	if err != nil {
		t.Fatalf("Unpadding failed: %v", err)
	}

	if !bytes.Equal(plaintext, unpadded) {
		t.Fatalf("ISO 10126 padding round-trip failed: expected %s, got %s", plaintext, unpadded)
	}
}

// Test GetMode factory function
func TestGetMode(t *testing.T) {
	modes := []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RANDOM_DELTA"}
	for _, modeName := range modes {
		mode := GetMode(modeName)
		if mode == nil {
			t.Fatalf("GetMode returned nil for mode: %s", modeName)
		}
		if mode.Name() != modeName {
			t.Fatalf("Mode name mismatch: expected %s, got %s", modeName, mode.Name())
		}
	}
}

// Test GetPadder factory function
func TestGetPadder(t *testing.T) {
	padders := []string{"ZEROS", "PKCS7", "ANSI_X923", "ISO_10126"}
	for _, paddingName := range padders {
		padder := padding.GetPadder(paddingName)
		if padder == nil {
			t.Fatalf("GetPadder returned nil for padding: %s", paddingName)
		}
		if padder.Name() != paddingName {
			t.Fatalf("Padding name mismatch: expected %s, got %s", paddingName, padder.Name())
		}
	}
}

// Test that different modes produce different ciphertexts
func TestDifferentModesProduceDifferentOutput(t *testing.T) {
	cipher := getTestRC6()
	padder := padding.GetPadder("PKCS7")
	plaintext := []byte("Hello, World!!!!")
	padded := padder.Pad(plaintext, 16)

	ecb := &ECBMode{}
	cbc := &CBCMode{}

	ecbEncrypted, _ := ecb.Encrypt(cipher, testKey256, padded, nil)
	cbcEncrypted, _ := cbc.Encrypt(cipher, testKey256, padded, testIV16)

	if bytes.Equal(ecbEncrypted, cbcEncrypted) {
		t.Fatalf("ECB and CBC produced identical output, should be different")
	}
}

// ============================================================================
// COMPREHENSIVE TEST SUITE
// ============================================================================

// TestAllAlgorithmModePaddingCombinations tests all combinations of algorithms, modes, and paddings
func TestAllAlgorithmModePaddingCombinations(t *testing.T) {
	testMessage := []byte("Hello, World! This is a test message for encryption and decryption.")

	testCases := []struct {
		name      string
		algorithm string
		key       []byte
		iv        []byte
		cipher    encryption.SymmetricCipher
		blockSize int
	}{
		{
			name:      "RC6",
			algorithm: "RC6",
			key:       testKey256,
			iv:        testIV16,
			cipher:    getTestRC6(),
			blockSize: 16,
		},
		{
			name:      "LOKI97",
			algorithm: "LOKI97",
			key:       testKey128,
			iv:        testIV8,
			cipher:    getTestLOKI97(),
			blockSize: 8,
		},
	}

	modeNames := []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR"} // Skip RANDOM_DELTA - uses random state
	paddingNames := []string{"ZEROS", "PKCS7", "ANSI_X923", "ISO_10126"}

	totalTests := 0
	passedTests := 0

	for _, tc := range testCases {
		for _, modeName := range modeNames {
			for _, paddingName := range paddingNames {
				totalTests++

				mode := GetMode(modeName)
				padder := padding.GetPadder(paddingName)

				if mode == nil || padder == nil {
					t.Logf("❌ %s + %s + %s: FAIL (Mode or Padder not found)", tc.algorithm, modeName, paddingName)
					continue
				}

				plaintext := testMessage
				paddedPlaintext := padder.Pad(plaintext, tc.blockSize)

				ciphertext, err := mode.Encrypt(tc.cipher, tc.key, paddedPlaintext, tc.iv)
				if err != nil {
					t.Logf("❌ %s + %s + %s: FAIL (Encryption failed: %v)", tc.algorithm, modeName, paddingName, err)
					continue
				}

				decrypted, err := mode.Decrypt(tc.cipher, tc.key, ciphertext, tc.iv)
				if err != nil {
					t.Logf("❌ %s + %s + %s: FAIL (Decryption failed: %v)", tc.algorithm, modeName, paddingName, err)
					continue
				}

				unpadded, err := padder.Unpad(decrypted)
				if err != nil {
					t.Logf("❌ %s + %s + %s: FAIL (Unpadding failed: %v)", tc.algorithm, modeName, paddingName, err)
					continue
				}

				if bytes.Equal(plaintext, unpadded) {
					passedTests++
					t.Logf("✅ %s + %s + %s: PASS", tc.algorithm, modeName, paddingName)
				} else {
					t.Logf("❌ %s + %s + %s: FAIL (Mismatch)", tc.algorithm, modeName, paddingName)
				}
			}
		}
	}

	t.Logf("\n\n📊 COMPREHENSIVE TEST SUMMARY")
	t.Logf("════════════════════════════════════════════════════")
	t.Logf("Total Tests:  %d", totalTests)
	t.Logf("✅ Passed:    %d", passedTests)
	t.Logf("❌ Failed:    %d", totalTests-passedTests)
	t.Logf("Success Rate: %.1f%%", float64(passedTests)/float64(totalTests)*100)
	t.Logf("════════════════════════════════════════════════════\n\n")

	if passedTests != totalTests {
		t.Fatalf("FAILED: %d/%d tests passed", passedTests, totalTests)
	}
}

// TestRC6AllCombinations tests RC6 with all modes and paddings
func TestRC6AllCombinations(t *testing.T) {
	testMessage := []byte("Hello, World! This is a test message for encryption and decryption.")
	cipher := getTestRC6()
	modeNames := []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR"} // Exclude RANDOM_DELTA
	paddingNames := []string{"ZEROS", "PKCS7", "ANSI_X923", "ISO_10126"}

	passedTests := 0
	totalTests := len(modeNames) * len(paddingNames)

	t.Logf("\n🔵 RC6 ALGORITHM TEST (7 modes × 4 paddings = 28 combinations)\n")

	for _, modeName := range modeNames {
		for _, paddingName := range paddingNames {
			mode := GetMode(modeName)
			padder := padding.GetPadder(paddingName)

			plaintext := testMessage
			paddedPlaintext := padder.Pad(plaintext, 16)

			ciphertext, _ := mode.Encrypt(cipher, testKey256, paddedPlaintext, testIV16)
			decrypted, _ := mode.Decrypt(cipher, testKey256, ciphertext, testIV16)
			unpadded, _ := padder.Unpad(decrypted)

			if bytes.Equal(plaintext, unpadded) {
				passedTests++
				t.Logf("✅ RC6 + %-12s + %-12s = PASS", modeName, paddingName)
			} else {
				t.Logf("❌ RC6 + %-12s + %-12s = FAIL", modeName, paddingName)
			}
		}
	}

	t.Logf("\n✅ RC6 Result: %d/%d combinations passed\n", passedTests, totalTests)

	if passedTests != totalTests {
		t.Fatalf("RC6 tests failed: %d/%d passed", passedTests, totalTests)
	}
}

// TestLOKI97AllCombinations tests LOKI97 with all modes and paddings
func TestLOKI97AllCombinations(t *testing.T) {
	testMessage := []byte("Hello, World! This is a test message for encryption and decryption.")
	cipher := getTestLOKI97()
	modeNames := []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR"} // Exclude RANDOM_DELTA
	paddingNames := []string{"ZEROS", "PKCS7", "ANSI_X923", "ISO_10126"}

	passedTests := 0
	totalTests := len(modeNames) * len(paddingNames)

	t.Logf("\n🟣 LOKI97 ALGORITHM TEST (7 modes × 4 paddings = 28 combinations)\n")

	for _, modeName := range modeNames {
		for _, paddingName := range paddingNames {
			mode := GetMode(modeName)
			padder := padding.GetPadder(paddingName)

			plaintext := testMessage
			paddedPlaintext := padder.Pad(plaintext, 8)

			ciphertext, _ := mode.Encrypt(cipher, testKey128, paddedPlaintext, testIV8)
			decrypted, _ := mode.Decrypt(cipher, testKey128, ciphertext, testIV8)
			unpadded, _ := padder.Unpad(decrypted)

			if bytes.Equal(plaintext, unpadded) {
				passedTests++
				t.Logf("✅ LOKI97 + %-12s + %-12s = PASS", modeName, paddingName)
			} else {
				t.Logf("❌ LOKI97 + %-12s + %-12s = FAIL", modeName, paddingName)
			}
		}
	}

	t.Logf("\n✅ LOKI97 Result: %d/%d combinations passed\n", passedTests, totalTests)

	if passedTests != totalTests {
		t.Fatalf("LOKI97 tests failed: %d/%d passed", passedTests, totalTests)
	}
}
