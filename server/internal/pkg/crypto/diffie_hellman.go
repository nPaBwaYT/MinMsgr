package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// DiffieHellman implements the Diffie-Hellman key exchange protocol
type DiffieHellman struct {
	p         *big.Int // Prime modulus
	g         *big.Int // Generator
	a         *big.Int // Private key
	publicKey *big.Int // Public key (g^a mod p)
}

// StandardPrimes contains standard large primes for DH
var StandardPrimes = map[string]string{
	"2048": "32317006071311007300714876688669951960444102669715484032476718642208077927270919675726183480381655661245343293396374297865145287051385931674764604283831268402492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947671312301751751",
	"1024": "179769313486231590772930519466302748567603895228499873636181257206420969034871862408894547503885626955961565867780667622669447862645141042050653017362278190337993529260869033400293513264135940736553263747264355074265425584788529331638813917571793533457644547111392391756803498693708657361331230430628711672835",
}

// NewDiffieHellman creates a new DH instance with a specific prime size (bits)
func NewDiffieHellman(primeBits int) (*DiffieHellman, error) {
	// Use a standard prime for common sizes
	var primeStr string
	var ok bool
	if primeStr, ok = StandardPrimes[fmt.Sprintf("%d", primeBits)]; !ok {
		// Generate a new safe prime
		var err error
		p, err := generateSafePrime(primeBits)
		if err != nil {
			return nil, err
		}
		primeStr = p.String()
	}

	p := new(big.Int)
	p.SetString(primeStr, 10)

	// Use g = 2 as the generator (commonly used)
	g := big.NewInt(2)

	return &DiffieHellman{
		p: p,
		g: g,
	}, nil
}

// GeneratePrivateKey generates a random private key
func (dh *DiffieHellman) GeneratePrivateKey() error {
	// Generate a random number in range [2, p-2]
	maxPrivateKey := new(big.Int)
	maxPrivateKey.Sub(dh.p, big.NewInt(2))

	a, err := rand.Int(rand.Reader, maxPrivateKey)
	if err != nil {
		return err
	}
	a.Add(a, big.NewInt(2))

	dh.a = a
	dh.computePublicKey()
	return nil
}

// computePublicKey computes the public key from the private key
func (dh *DiffieHellman) computePublicKey() {
	dh.publicKey = new(big.Int)
	dh.publicKey.Exp(dh.g, dh.a, dh.p)
}

// GetPublicKey returns the public key as a byte slice
func (dh *DiffieHellman) GetPublicKey() []byte {
	if dh.publicKey == nil {
		return nil
	}
	return dh.publicKey.Bytes()
}

// GetPrime returns the prime modulus as a byte slice
func (dh *DiffieHellman) GetPrime() []byte {
	return dh.p.Bytes()
}

// GetGenerator returns the generator as a byte slice
func (dh *DiffieHellman) GetGenerator() []byte {
	return dh.g.Bytes()
}

// ComputeSharedSecret computes the shared secret using the other party's public key
func (dh *DiffieHellman) ComputeSharedSecret(otherPublicKeyBytes []byte) ([]byte, error) {
	if dh.a == nil {
		return nil, fmt.Errorf("private key not generated")
	}

	otherPublicKey := new(big.Int)
	otherPublicKey.SetBytes(otherPublicKeyBytes)

	// Compute: (otherPublicKey^a) mod p
	sharedSecret := new(big.Int)
	sharedSecret.Exp(otherPublicKey, dh.a, dh.p)

	return sharedSecret.Bytes(), nil
}

// generateSafePrime generates a safe prime for DH key exchange
func generateSafePrime(bits int) (*big.Int, error) {
	for {
		p, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, err
		}

		// Check if (p-1)/2 is also prime (safe prime)
		q := new(big.Int)
		q.Sub(p, big.NewInt(1))
		q.Div(q, big.NewInt(2))

		if q.ProbablyPrime(20) {
			return p, nil
		}
	}
}

// SetParameters sets the DH parameters manually (for testing or specific parameters)
func (dh *DiffieHellman) SetParameters(p *big.Int, g *big.Int) {
	dh.p = p
	dh.g = g
}

// KeyAgreement represents a complete key agreement transaction
type KeyAgreement struct {
	PartyA *DiffieHellman
	PartyB *DiffieHellman
}

// NewKeyAgreement creates a new key agreement between two parties
func NewKeyAgreement(primeBits int) (*KeyAgreement, error) {
	partyA, err := NewDiffieHellman(primeBits)
	if err != nil {
		return nil, err
	}

	partyB, err := NewDiffieHellman(primeBits)
	if err != nil {
		return nil, err
	}

	// Share same prime and generator
	partyB.p = partyA.p
	partyB.g = partyA.g

	return &KeyAgreement{
		PartyA: partyA,
		PartyB: partyB,
	}, nil
}

// PerformKeyExchange performs the complete key exchange
func (ka *KeyAgreement) PerformKeyExchange() ([]byte, []byte, error) {
	// Both parties generate their private keys
	err := ka.PartyA.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}

	err = ka.PartyB.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}

	// Exchange public keys and compute shared secrets
	secretA, err := ka.PartyA.ComputeSharedSecret(ka.PartyB.GetPublicKey())
	if err != nil {
		return nil, nil, err
	}

	secretB, err := ka.PartyB.ComputeSharedSecret(ka.PartyA.GetPublicKey())
	if err != nil {
		return nil, nil, err
	}

	return secretA, secretB, nil
}
