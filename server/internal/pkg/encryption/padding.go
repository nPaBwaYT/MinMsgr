// server/internal/pkg/encryption/padding.go
package encryption

import "errors"

type PaddingScheme interface {
    Pad(block []byte, blockSize int) []byte
    Unpad(block []byte, blockSize int) ([]byte, error)
}

type PKCS7Padding struct{}

func (p *PKCS7Padding) Pad(block []byte, blockSize int) []byte {
    padding := blockSize - len(block)%blockSize
    padtext := make([]byte, len(block)+padding)
    copy(padtext, block)
    for i := len(block); i < len(padtext); i++ {
        padtext[i] = byte(padding)
    }
    return padtext
}

func (p *PKCS7Padding) Unpad(block []byte, blockSize int) ([]byte, error) {
    if len(block) == 0 {
        return nil, errors.New("empty block")
    }
    padding := int(block[len(block)-1])
    if padding > len(block) || padding > blockSize {
        return nil, errors.New("invalid padding")
    }
    return block[:len(block)-padding], nil
}

// Аналогично для других схем набивки (Zeros, ANSI X.923, ISO 10126)