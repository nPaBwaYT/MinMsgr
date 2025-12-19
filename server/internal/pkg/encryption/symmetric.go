// server/internal/pkg/encryption/symmetric.go
package encryption

import "errors"

var (
    ErrInvalidKeySize   = errors.New("invalid key size")
    ErrInvalidBlockSize = errors.New("invalid block size")
    ErrInvalidIV        = errors.New("invalid IV")
)

type SymmetricAlgorithm interface {
    Encrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error)
    Decrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error)
    KeySize() int
    BlockSize() int
    Name() string
}

// server/internal/pkg/encryption/algorithms/custom_cipher.go
