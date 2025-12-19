package modes

import (
	"crypto/rand"
	"fmt"

	"MinMsgr/server/internal/pkg/encryption"
)

// Mode interface defines the encryption mode contract
type Mode interface {
	Encrypt(cipher encryption.SymmetricCipher, key []byte, plaintext []byte, iv []byte) ([]byte, error)
	Decrypt(cipher encryption.SymmetricCipher, key []byte, ciphertext []byte, iv []byte) ([]byte, error)
	RequiresIV() bool
	Name() string
}

// ECBMode - Electronic Codebook Mode (no IV required)
type ECBMode struct{}

func (e *ECBMode) Name() string {
	return "ECB"
}

func (e *ECBMode) RequiresIV() bool {
	return false
}

func (e *ECBMode) Encrypt(cipher encryption.SymmetricCipher, key []byte, plaintext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext length must be multiple of block size (%d)", blockSize)
	}

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += blockSize {
		block, err := cipher.Encrypt(key, plaintext[i:i+blockSize])
		if err != nil {
			return nil, err
		}
		copy(ciphertext[i:], block)
	}

	return ciphertext, nil
}

func (e *ECBMode) Decrypt(cipher encryption.SymmetricCipher, key []byte, ciphertext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size (%d)", blockSize)
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		block, err := cipher.Decrypt(key, ciphertext[i:i+blockSize])
		if err != nil {
			return nil, err
		}
		copy(plaintext[i:], block)
	}

	return plaintext, nil
}

// CBCMode - Cipher Block Chaining Mode
type CBCMode struct{}

func (c *CBCMode) Name() string {
	return "CBC"
}

func (c *CBCMode) RequiresIV() bool {
	return true
}

func (c *CBCMode) Encrypt(cipher encryption.SymmetricCipher, key []byte, plaintext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}
	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext length must be multiple of block size (%d)", blockSize)
	}

	ciphertext := make([]byte, len(plaintext))
	prevCipherBlock := make([]byte, blockSize)
	copy(prevCipherBlock, iv)

	for i := 0; i < len(plaintext); i += blockSize {
		// XOR plaintext with previous ciphertext
		block := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			block[j] = plaintext[i+j] ^ prevCipherBlock[j]
		}

		// Encrypt
		encryptedBlock, err := cipher.Encrypt(key, block)
		if err != nil {
			return nil, err
		}
		copy(ciphertext[i:], encryptedBlock)
		copy(prevCipherBlock, encryptedBlock)
	}

	return ciphertext, nil
}

func (c *CBCMode) Decrypt(cipher encryption.SymmetricCipher, key []byte, ciphertext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size (%d)", blockSize)
	}

	plaintext := make([]byte, len(ciphertext))
	prevCipherBlock := make([]byte, blockSize)
	copy(prevCipherBlock, iv)

	for i := 0; i < len(ciphertext); i += blockSize {
		// Decrypt
		decryptedBlock, err := cipher.Decrypt(key, ciphertext[i:i+blockSize])
		if err != nil {
			return nil, err
		}

		// XOR with previous ciphertext
		for j := 0; j < blockSize; j++ {
			plaintext[i+j] = decryptedBlock[j] ^ prevCipherBlock[j]
		}
		copy(prevCipherBlock, ciphertext[i:i+blockSize])
	}

	return plaintext, nil
}

// PCBCMode - Propagating Cipher Block Chaining Mode
type PCBCMode struct{}

func (p *PCBCMode) Name() string {
	return "PCBC"
}

func (p *PCBCMode) RequiresIV() bool {
	return true
}

func (p *PCBCMode) Encrypt(cipher encryption.SymmetricCipher, key []byte, plaintext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}
	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext length must be multiple of block size (%d)", blockSize)
	}

	ciphertext := make([]byte, len(plaintext))
	prev := make([]byte, blockSize)
	copy(prev, iv)

	for i := 0; i < len(plaintext); i += blockSize {
		// XOR with previous result
		block := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			block[j] = plaintext[i+j] ^ prev[j]
		}

		// Encrypt
		encryptedBlock, err := cipher.Encrypt(key, block)
		if err != nil {
			return nil, err
		}
		copy(ciphertext[i:], encryptedBlock)

		// Update previous (XOR plaintext and ciphertext)
		for j := 0; j < blockSize; j++ {
			prev[j] = plaintext[i+j] ^ encryptedBlock[j]
		}
	}

	return ciphertext, nil
}

func (p *PCBCMode) Decrypt(cipher encryption.SymmetricCipher, key []byte, ciphertext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of block size (%d)", blockSize)
	}

	plaintext := make([]byte, len(ciphertext))
	prev := make([]byte, blockSize)
	copy(prev, iv)

	for i := 0; i < len(ciphertext); i += blockSize {
		// Decrypt
		decryptedBlock, err := cipher.Decrypt(key, ciphertext[i:i+blockSize])
		if err != nil {
			return nil, err
		}

		// XOR with previous value
		for j := 0; j < blockSize; j++ {
			plaintext[i+j] = decryptedBlock[j] ^ prev[j]
		}

		// Update previous (XOR plaintext and ciphertext)
		for j := 0; j < blockSize; j++ {
			prev[j] = plaintext[i+j] ^ ciphertext[i+j]
		}
	}

	return plaintext, nil
}

// CFBMode - Cipher Feedback Mode
type CFBMode struct{}

func (c *CFBMode) Name() string {
	return "CFB"
}

func (c *CFBMode) RequiresIV() bool {
	return true
}

func (c *CFBMode) Encrypt(cipher encryption.SymmetricCipher, key []byte, plaintext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}

	ciphertext := make([]byte, len(plaintext))
	register := make([]byte, blockSize)
	copy(register, iv)

	for i := 0; i < len(plaintext); i += blockSize {
		endIdx := i + blockSize
		if endIdx > len(plaintext) {
			endIdx = len(plaintext)
		}
		blockLen := endIdx - i

		// Encrypt the register
		encrypted, err := cipher.Encrypt(key, register)
		if err != nil {
			return nil, err
		}

		// XOR with plaintext
		for j := 0; j < blockLen; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ encrypted[j]
		}

		// Shift register and add new ciphertext
		copy(register, register[blockLen:])
		copy(register[blockSize-blockLen:], ciphertext[i:endIdx])
	}

	return ciphertext, nil
}

func (c *CFBMode) Decrypt(cipher encryption.SymmetricCipher, key []byte, ciphertext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}

	plaintext := make([]byte, len(ciphertext))
	register := make([]byte, blockSize)
	copy(register, iv)

	for i := 0; i < len(ciphertext); i += blockSize {
		endIdx := i + blockSize
		if endIdx > len(ciphertext) {
			endIdx = len(ciphertext)
		}
		blockLen := endIdx - i

		// Encrypt the register
		encrypted, err := cipher.Encrypt(key, register)
		if err != nil {
			return nil, err
		}

		// XOR with ciphertext
		for j := 0; j < blockLen; j++ {
			plaintext[i+j] = ciphertext[i+j] ^ encrypted[j]
		}

		// Shift register and add new ciphertext
		copy(register, register[blockLen:])
		copy(register[blockSize-blockLen:], ciphertext[i:endIdx])
	}

	return plaintext, nil
}

// OFBMode - Output Feedback Mode
type OFBMode struct{}

func (o *OFBMode) Name() string {
	return "OFB"
}

func (o *OFBMode) RequiresIV() bool {
	return true
}

func (o *OFBMode) Encrypt(cipher encryption.SymmetricCipher, key []byte, plaintext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}

	ciphertext := make([]byte, len(plaintext))
	keystream := make([]byte, blockSize)
	copy(keystream, iv)

	for i := 0; i < len(plaintext); i += blockSize {
		endIdx := i + blockSize
		if endIdx > len(plaintext) {
			endIdx = len(plaintext)
		}
		blockLen := endIdx - i

		// Generate keystream
		generated, err := cipher.Encrypt(key, keystream)
		if err != nil {
			return nil, err
		}

		// XOR with plaintext
		for j := 0; j < blockLen; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ generated[j]
		}

		// Update keystream
		copy(keystream, generated)
	}

	return ciphertext, nil
}

func (o *OFBMode) Decrypt(cipher encryption.SymmetricCipher, key []byte, ciphertext []byte, iv []byte) ([]byte, error) {
	// OFB decryption is the same as encryption
	return o.Encrypt(cipher, key, ciphertext, iv)
}

// CTRMode - Counter Mode
type CTRMode struct{}

func (c *CTRMode) Name() string {
	return "CTR"
}

func (c *CTRMode) RequiresIV() bool {
	return true
}

func (c *CTRMode) Encrypt(cipher encryption.SymmetricCipher, key []byte, plaintext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}

	ciphertext := make([]byte, len(plaintext))
	counter := make([]byte, blockSize)
	copy(counter, iv)

	for i := 0; i < len(plaintext); i += blockSize {
		endIdx := i + blockSize
		if endIdx > len(plaintext) {
			endIdx = len(plaintext)
		}
		blockLen := endIdx - i

		// Encrypt counter
		keystream, err := cipher.Encrypt(key, counter)
		if err != nil {
			return nil, err
		}

		// XOR with plaintext
		for j := 0; j < blockLen; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ keystream[j]
		}

		// Increment counter
		incrementCounter(counter)
	}

	return ciphertext, nil
}

func (c *CTRMode) Decrypt(cipher encryption.SymmetricCipher, key []byte, ciphertext []byte, iv []byte) ([]byte, error) {
	// CTR decryption is the same as encryption
	return c.Encrypt(cipher, key, ciphertext, iv)
}

// RandomDeltaMode - Stream cipher mode with random delta
type RandomDeltaMode struct{}

func (r *RandomDeltaMode) Name() string {
	return "RANDOM_DELTA"
}

func (r *RandomDeltaMode) RequiresIV() bool {
	return true
}

func (r *RandomDeltaMode) Encrypt(cipher encryption.SymmetricCipher, key []byte, plaintext []byte, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}

	ciphertext := make([]byte, len(plaintext))
	state := make([]byte, blockSize)
	copy(state, iv)

	for i := 0; i < len(plaintext); i += blockSize {
		endIdx := i + blockSize
		if endIdx > len(plaintext) {
			endIdx = len(plaintext)
		}
		blockLen := endIdx - i

		// Generate keystream
		keystream, err := cipher.Encrypt(key, state)
		if err != nil {
			return nil, err
		}

		// XOR with plaintext
		for j := 0; j < blockLen; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ keystream[j]
		}

		// Generate random delta and add to state
		delta := make([]byte, blockSize)
		rand.Read(delta)
		for j := 0; j < blockSize; j++ {
			state[j] ^= delta[j]
		}
	}

	return ciphertext, nil
}

func (r *RandomDeltaMode) Decrypt(cipher encryption.SymmetricCipher, key []byte, ciphertext []byte, iv []byte) ([]byte, error) {
	// For random delta, we need to store the deltas
	// This is simplified - in production, deltas should be transmitted with ciphertext
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must be %d", blockSize)
	}

	plaintext := make([]byte, len(ciphertext))
	state := make([]byte, blockSize)
	copy(state, iv)

	for i := 0; i < len(ciphertext); i += blockSize {
		endIdx := i + blockSize
		if endIdx > len(ciphertext) {
			endIdx = len(ciphertext)
		}
		blockLen := endIdx - i

		// Generate keystream
		keystream, err := cipher.Encrypt(key, state)
		if err != nil {
			return nil, err
		}

		// XOR with ciphertext
		for j := 0; j < blockLen; j++ {
			plaintext[i+j] = ciphertext[i+j] ^ keystream[j]
		}

		// Generate random delta and add to state
		delta := make([]byte, blockSize)
		rand.Read(delta)
		for j := 0; j < blockSize; j++ {
			state[j] ^= delta[j]
		}
	}

	return plaintext, nil
}

// Helper function to increment counter
func incrementCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

// GetMode returns a Mode implementation for the given mode name
func GetMode(modeName string) Mode {
	switch modeName {
	case "ECB":
		return &ECBMode{}
	case "CBC":
		return &CBCMode{}
	case "PCBC":
		return &PCBCMode{}
	case "CFB":
		return &CFBMode{}
	case "OFB":
		return &OFBMode{}
	case "CTR":
		return &CTRMode{}
	case "RANDOM_DELTA":
		return &RandomDeltaMode{}
	default:
		return nil
	}
}
