// server/internal/pkg/encryption/modes.go
package encryption

type BlockMode interface {
    Encrypt(blocks [][]byte, key []byte, iv []byte) ([][]byte, error)
    Decrypt(blocks [][]byte, key []byte, iv []byte) ([][]byte, error)
}

type ECB struct{}

func (e *ECB) Encrypt(blocks [][]byte, key []byte, iv []byte) ([][]byte, error) {
    // TODO: Реализация ECB mode
    return blocks, nil
}

func (e *ECB) Decrypt(blocks [][]byte, key []byte, iv []byte) ([][]byte, error) {
    // TODO: Реализация ECB mode
    return blocks, nil
}

// Аналогично для других режимов (CBC, PCBC, CFB, OFB, CTR, RandomDelta)