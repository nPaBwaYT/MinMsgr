package encryption

// SymmetricCipher is the interface that all symmetric encryption algorithms must implement
type SymmetricCipher interface {
	// Encrypt encrypts plaintext with the given key
	Encrypt(key []byte, plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext with the given key
	Decrypt(key []byte, ciphertext []byte) ([]byte, error)

	// BlockSize returns the block size in bytes
	BlockSize() int

	// KeySize returns the required key size in bytes
	KeySize() int

	// Name returns the algorithm name
	Name() string
}

const (
	LOKI97BlockSize = 8  // 64-bit blocks (8 bytes)
	LOKI97KeySize   = 16 // 128-bit key (16 bytes) - LOKI97 requires at least 128-bit keys per specification

	RC6BlockSize = 16 // 128-bit blocks (16 bytes)
)

type LOKI97 struct {
	roundKeys []uint64
}

type RC6 struct {
	s []uint32
	w int // word size in bits
	r int // number of rounds
}
