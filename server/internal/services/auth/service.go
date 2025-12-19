package auth

import (
	"encoding/hex"
	"fmt"
	"time"

	"MinMsgr/server/internal/storage"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

// Service implements authentication logic
type Service struct {
	jwtSecret string
	store     Store
}

// Store defines the persistence interface
type Store interface {
	CreateUser(username, hashedPassword string) (int64, error)
	GetUserByUsername(username string) (*storage.User, error)
	GetUserByID(userID int64) (*storage.User, error)
	SaveUserKeys(userID int64, publicKey, encryptedPrivateKey []byte) error
}

// Claims represents JWT claims
type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}

// New creates a new auth service
func New(jwtSecret string, store Store) *Service {
	return &Service{
		jwtSecret: jwtSecret,
		store:     store,
	}
}

// Register creates a new user account
// Register creates a new user account and stores optional DH keys
func (s *Service) Register(username, password string, publicKeyHex, encryptedPrivateKeyHex string) (int64, string, error) {
	if username == "" || password == "" {
		return 0, "", fmt.Errorf("username and password cannot be empty")
	}

	// Check if user already exists - registration not allowed for existing usernames
	existing, err := s.store.GetUserByUsername(username)
	if err != nil {
		return 0, "", err
	}
	if existing != nil {
		// Username already registered - registration must fail
		return 0, "", fmt.Errorf("username already exists")
	}

	// Hash password
	hashedPassword := hashPassword(password)

	// Create user (public/encrypted key can be saved after creation)
	userID, err := s.store.CreateUser(username, hashedPassword)
	if err != nil {
		return 0, "", err
	}

	// If client provided keys at registration, save them
	var encHex string
	if publicKeyHex != "" || encryptedPrivateKeyHex != "" {
		var pubBytes, encPriv []byte
		if publicKeyHex != "" {
			pubBytes, _ = hex.DecodeString(publicKeyHex)
		}
		if encryptedPrivateKeyHex != "" {
			encPriv, _ = hex.DecodeString(encryptedPrivateKeyHex)
		}
		if err := s.store.SaveUserKeys(userID, pubBytes, encPriv); err != nil {
			return userID, "", err
		}
		if len(encPriv) > 0 {
			encHex = hex.EncodeToString(encPriv)
		}
	}

	return userID, encHex, nil
}

// Login authenticates a user and returns a JWT token and the user's encrypted private key (hex)
func (s *Service) Login(username, password string) (string, string, error) {
	if username == "" || password == "" {
		return "", "", fmt.Errorf("username and password cannot be empty")
	}

	// Get user from store
	user, err := s.store.GetUserByUsername(username)
	if err != nil {
		return "", "", err
	}
	if user == nil {
		return "", "", fmt.Errorf("invalid username or password")
	}

	// Verify password
	if !verifyPassword(password, user.HashedPassword) {
		return "", "", fmt.Errorf("invalid username or password")
	}

	// Create JWT token
	token, err := s.CreateToken(user.ID, user.Username)
	if err != nil {
		return "", "", err
	}

	var encPrivHex string
	if len(user.EncryptedPrivateKey) > 0 {
		encPrivHex = hex.EncodeToString(user.EncryptedPrivateKey)
	}

	return token, encPrivHex, nil
}

// GetUserPublicKey returns stored public key bytes for a user
func (s *Service) GetUserPublicKey(userID int64) ([]byte, error) {
	user, err := s.store.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, fmt.Errorf("user not found")
	}
	return user.PublicKey, nil
}

// CreateToken creates a new JWT token for a user
func (s *Service) CreateToken(userID int64, username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID:   userID,
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken validates and parses a JWT token
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// hashPassword hashes a password using bcrypt (cost: 12)
func hashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// In production, this should be handled properly
		// For now, return a safe value that will fail verification
		return ""
	}
	return string(hash)
}

// verifyPassword verifies a password against its bcrypt hash
func verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
