package encryption

import (
	"encoding/binary"
	"fmt"
)

const (
	RC6KeySize = 32 // 256-bit key
)

// NewRC6 creates a new RC6 cipher with the given key
func NewRC6(key []byte) (*RC6, error) {
	if len(key) < 16 || len(key) > 32 {
		return nil, fmt.Errorf("RC6 key must be between 16 and 32 bytes")
	}

	cipher := &RC6{
		w: 32,                 // 32-bit words (128-bit blocks)
		r: 20,                 // 20 rounds
		s: make([]uint32, 44), // 2(r+2) = 44 for 20 rounds
	}

	cipher.expandKey(key)
	return cipher, nil
}

// BlockSize returns the block size of RC6
func (r *RC6) BlockSize() int {
	return RC6BlockSize
}

// KeySize returns the key size of RC6
func (r *RC6) KeySize() int {
	return RC6KeySize
}

// Name returns the cipher name
func (r *RC6) Name() string {
	return "RC6"
}

// Encrypt encrypts a 128-bit block
func (r *RC6) Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(plaintext) != RC6BlockSize {
		return nil, fmt.Errorf("plaintext must be %d bytes, got %d", RC6BlockSize, len(plaintext))
	}

	a := binary.LittleEndian.Uint32(plaintext[0:4])
	b := binary.LittleEndian.Uint32(plaintext[4:8])
	c := binary.LittleEndian.Uint32(plaintext[8:12])
	d := binary.LittleEndian.Uint32(plaintext[12:16])

	b = b + r.s[0]
	d = d + r.s[1]

	for i := 1; i <= r.r; i++ {
		t := rotl32(b*(2*b+1), 5)
		u := rotl32(d*(2*d+1), 5)
		a = rotl32(a^t, u%32) + r.s[2*i]
		c = rotl32(c^u, t%32) + r.s[2*i+1]

		a, b, c, d = b, c, d, a
	}

	a = a + r.s[2*r.r+2]
	c = c + r.s[2*r.r+3]

	ciphertext := make([]byte, RC6BlockSize)
	binary.LittleEndian.PutUint32(ciphertext[0:4], a)
	binary.LittleEndian.PutUint32(ciphertext[4:8], b)
	binary.LittleEndian.PutUint32(ciphertext[8:12], c)
	binary.LittleEndian.PutUint32(ciphertext[12:16], d)

	return ciphertext, nil
}

// Decrypt decrypts a 128-bit block
func (r *RC6) Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != RC6BlockSize {
		return nil, fmt.Errorf("ciphertext must be %d bytes, got %d", RC6BlockSize, len(ciphertext))
	}

	a := binary.LittleEndian.Uint32(ciphertext[0:4])
	b := binary.LittleEndian.Uint32(ciphertext[4:8])
	c := binary.LittleEndian.Uint32(ciphertext[8:12])
	d := binary.LittleEndian.Uint32(ciphertext[12:16])

	c = c - r.s[2*r.r+3]
	a = a - r.s[2*r.r+2]

	for i := r.r; i >= 1; i-- {
		a, b, c, d = d, a, b, c

		u := rotl32(d*(2*d+1), 5)
		t := rotl32(b*(2*b+1), 5)
		c = rotr32(c-r.s[2*i+1], t%32) ^ u
		a = rotr32(a-r.s[2*i], u%32) ^ t
	}

	d = d - r.s[1]
	b = b - r.s[0]

	plaintext := make([]byte, RC6BlockSize)
	binary.LittleEndian.PutUint32(plaintext[0:4], a)
	binary.LittleEndian.PutUint32(plaintext[4:8], b)
	binary.LittleEndian.PutUint32(plaintext[8:12], c)
	binary.LittleEndian.PutUint32(plaintext[12:16], d)

	return plaintext, nil
}

// expandKey expands the key into round keys
func (r *RC6) expandKey(key []byte) {
	// Copy key into L array
	c := (len(key) + 3) / 4
	L := make([]uint32, c)
	for i := 0; i < len(key); i++ {
		L[i/4] |= uint32(key[i]) << uint((i%4)*8)
	}

	// Mix in the magic constants
	p32 := uint32(0xB7E15163)
	q32 := uint32(0x9E3779B9)

	r.s[0] = p32
	for i := 1; i < 44; i++ {
		r.s[i] = r.s[i-1] + q32
	}

	// Key-dependent rounds
	a, b := uint32(0), uint32(0)
	i, j := 0, 0
	for k := 0; k < 3*44; k++ {
		r.s[i] = rotl32(r.s[i]+a+b, 3)
		a = r.s[i]
		L[j] = rotl32(L[j]+a+b, (a+b)%32)
		b = L[j]
		i = (i + 1) % 44
		j = (j + 1) % c
	}
}

// rotl32 rotates a 32-bit value left by n bits
func rotl32(x uint32, n uint32) uint32 {
	return (x << n) | (x >> (32 - n))
}

// rotr32 rotates a 32-bit value right by n bits
func rotr32(x uint32, n uint32) uint32 {
	return (x >> n) | (x << (32 - n))
}
