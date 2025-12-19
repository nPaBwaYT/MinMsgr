package padding

import (
	"crypto/rand"
	"fmt"
)

// Padder interface defines the padding contract
type Padder interface {
	Pad(data []byte, blockSize int) []byte
	Unpad(data []byte) ([]byte, error)
	Name() string
}

// ZeroPadding - Pad with zero bytes
type ZeroPadding struct{}

func (z *ZeroPadding) Name() string {
	return "ZEROS"
}

func (z *ZeroPadding) Pad(data []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(data) % blockSize)
	if paddingLen == 0 {
		paddingLen = blockSize
	}
	padding := make([]byte, paddingLen)
	// All zeros
	return append(data, padding...)
}

func (z *ZeroPadding) Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padded data")
	}

	// Remove trailing zeros
	i := len(data) - 1
	for i >= 0 && data[i] == 0 {
		i--
	}

	return data[:i+1], nil
}

// PKCS7Padding - PKCS#7 padding scheme
type PKCS7Padding struct{}

func (p *PKCS7Padding) Name() string {
	return "PKCS7"
}

func (p *PKCS7Padding) Pad(data []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(data) % blockSize)
	if paddingLen == 0 {
		paddingLen = blockSize
	}
	padding := make([]byte, paddingLen)
	for i := 0; i < paddingLen; i++ {
		padding[i] = byte(paddingLen)
	}
	return append(data, padding...)
}

func (p *PKCS7Padding) Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padded data")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen > len(data) || paddingLen == 0 {
		return nil, fmt.Errorf("invalid padding length")
	}

	// Verify padding
	for i := len(data) - paddingLen; i < len(data); i++ {
		if data[i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-paddingLen], nil
}

// ANSIX923Padding - ANSI X.923 padding scheme
type ANSIX923Padding struct{}

func (a *ANSIX923Padding) Name() string {
	return "ANSI_X923"
}

func (a *ANSIX923Padding) Pad(data []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(data) % blockSize)
	if paddingLen == 0 {
		paddingLen = blockSize
	}
	padding := make([]byte, paddingLen)
	// All zeros except last byte which is the padding length
	padding[paddingLen-1] = byte(paddingLen)
	return append(data, padding...)
}

func (a *ANSIX923Padding) Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padded data")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen > len(data) || paddingLen == 0 {
		return nil, fmt.Errorf("invalid padding length")
	}

	// Verify padding (all zeros except last byte)
	for i := len(data) - paddingLen; i < len(data)-1; i++ {
		if data[i] != 0 {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-paddingLen], nil
}

// ISO10126Padding - ISO 10126 padding scheme
type ISO10126Padding struct{}

func (i *ISO10126Padding) Name() string {
	return "ISO_10126"
}

func (i *ISO10126Padding) Pad(data []byte, blockSize int) []byte {
	paddingLen := blockSize - (len(data) % blockSize)
	if paddingLen == 0 {
		paddingLen = blockSize
	}
	padding := make([]byte, paddingLen)
	// Random bytes except last byte which is the padding length
	rand.Read(padding[:paddingLen-1])
	padding[paddingLen-1] = byte(paddingLen)
	return append(data, padding...)
}

func (i *ISO10126Padding) Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid padded data")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen > len(data) || paddingLen == 0 {
		return nil, fmt.Errorf("invalid padding length")
	}

	return data[:len(data)-paddingLen], nil
}

// GetPadder returns a Padder implementation for the given padding name
func GetPadder(paddingName string) Padder {
	switch paddingName {
	case "ZEROS":
		return &ZeroPadding{}
	case "PKCS7":
		return &PKCS7Padding{}
	case "ANSI_X923":
		return &ANSIX923Padding{}
	case "ISO_10126":
		return &ISO10126Padding{}
	default:
		return nil
	}
}
