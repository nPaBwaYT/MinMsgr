package protocol

import (
	"time"
)

// EncryptionAlgorithm type for available algorithms
type EncryptionAlgorithm string

const (
	LOKI97 EncryptionAlgorithm = "LOKI97"
	RC6    EncryptionAlgorithm = "RC6"
)

// EncryptionMode type for block cipher modes
type EncryptionMode string

const (
	ECB         EncryptionMode = "ECB"
	CBC         EncryptionMode = "CBC"
	PCBC        EncryptionMode = "PCBC"
	CFB         EncryptionMode = "CFB"
	OFB         EncryptionMode = "OFB"
	CTR         EncryptionMode = "CTR"
	RandomDelta EncryptionMode = "RANDOM_DELTA"
)

// PaddingMode type for padding schemes
type PaddingMode string

const (
	Zeros    PaddingMode = "ZEROS"
	PKCS7    PaddingMode = "PKCS7"
	ANSI     PaddingMode = "ANSI_X923"
	ISO10126 PaddingMode = "ISO_10126"
)

// WebSocket deadlines
var (
	ReadDeadline  = time.Now().Add(time.Hour)
	WriteDeadline = time.Now().Add(time.Second * 10)
)

// User represents a registered user
type User struct {
	ID             int64
	Username       string
	HashedPassword string
	CreatedAt      int64
}

// Contact represents a contact relationship between two users
type Contact struct {
	ID        int64
	User1ID   int64
	User2ID   int64
	Username  string
	Status    string // "pending", "accepted", "blocked"
	CreatedAt int64
}

// Chat represents an encrypted chat room
type Chat struct {
	ID        int64
	User1ID   int64
	User2ID   int64
	Algorithm string
	Mode      string
	Padding   string
	Status    string // "active", "closed"
	CreatedAt int64
	ClosedAt  *int64
	// DH parameters for key exchange
	DHPrime     []byte
	DHGenerator []byte
}

// Message represents a message in a chat
type Message struct {
	ID               int64
	ChatID           string
	SenderID         string
	EncryptedContent []byte
	IV               []byte
	Timestamp        int64
}

// DiffieHellmanParams holds the public parameters for DH key exchange
type DiffieHellmanParams struct {
	Prime     []byte // modulus p
	Generator []byte // generator g
}

// DiffieHellmanPublicKey represents one party's public key
type DiffieHellmanPublicKey struct {
	Value []byte // g^a mod p or g^b mod p
}

// SessionKey represents a shared session key for encrypting a chat
type SessionKey struct {
	ChatID    int64
	Key       []byte
	IV        []byte // Initialization vector for modes requiring it
	CreatedAt int64
}

// GatewayResponse represents a response sent back to clients
type GatewayResponse struct {
	ID        string      `json:"id"`
	UserID    int64       `json:"user_id"`
	Type      string      `json:"type"`
	Status    string      `json:"status"` // "success", "error"
	Data      interface{} `json:"data"`
	Error     string      `json:"error"`
	Timestamp int64       `json:"timestamp"`
}

// EncryptedMessage represents ciphertext being transmitted
type EncryptedMessage struct {
	ID         int64  `json:"id,omitempty"`
	ChatID     int64  `json:"chat_id"`
	SenderID   int64  `json:"sender_id"`
	Ciphertext []byte `json:"ciphertext"`
	IV         []byte `json:"iv"`
	Timestamp  int64  `json:"timestamp"`
	FileName   string `json:"file_name,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
}

// ContactRequest represents a contact management request
type ContactRequest struct {
	Action    string `json:"action"` // "add", "accept", "reject", "remove"
	UserID    int64  `json:"user_id"`
	ContactID int64  `json:"contact_id"`
}

// ContactResponse represents a contact management response
type ContactResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// GetContactsResponse returns user's contacts
type GetContactsResponse struct {
	Pending  []Contact `json:"pending"`
	Accepted []Contact `json:"accepted"`
}

// ChatCreateRequest represents a chat creation request
type ChatCreateRequest struct {
	User1ID   int64  `json:"user1_id"`
	User2ID   int64  `json:"user2_id"`
	Algorithm string `json:"algorithm"`
	Mode      string `json:"mode"`
	Padding   string `json:"padding"`
}

// ChatResponse represents a chat operation response
type ChatResponse struct {
	Success   bool   `json:"success"`
	ChatID    int64  `json:"chat_id,omitempty"`
	User1ID   int64  `json:"user1_id,omitempty"`
	User2ID   int64  `json:"user2_id,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Padding   string `json:"padding,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// GetUserChatsResponse returns user's chats
type GetUserChatsResponse struct {
	Chats []*Chat `json:"chats"`
}

// WebSocketEvent represents a real-time event sent over WebSocket
type WebSocketEvent struct {
	Type      string      `json:"type"`    // "contact_request", "chat_created", "message", etc.
	UserID    int64       `json:"user_id"` // Target user ID
	Data      interface{} `json:"data"`    // Event data
	Timestamp int64       `json:"timestamp"`
}

// ContactRequestEvent data
type ContactRequestEvent struct {
	ContactID int64  `json:"contact_id"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	Status    string `json:"status"` // "pending" or other status
	Action    string `json:"action"` // "new", "accepted", "rejected"
}

// ChatEvent data
type ChatEvent struct {
	ChatID    int64  `json:"chat_id"`
	User1ID   int64  `json:"user1_id"`
	User2ID   int64  `json:"user2_id"`
	Action    string `json:"action"` // "created", "closed"
	Timestamp int64  `json:"timestamp"`
}

// DHInitEvent sent when initiating DH exchange for a chat
type DHInitEvent struct {
	ChatID    int64  `json:"chat_id"`
	UserID    int64  `json:"user_id"`
	Prime     string `json:"prime"`     // base64 encoded
	Generator string `json:"generator"` // base64 encoded
	Timestamp int64  `json:"timestamp"`
}

// DHPublicKeyEvent sent when exchanging public keys
type DHPublicKeyEvent struct {
	ChatID    int64  `json:"chat_id"`
	UserID    int64  `json:"user_id"`
	PublicKey string `json:"public_key"` // base64 encoded
	Timestamp int64  `json:"timestamp"`
}

// DHCompleteEvent sent when key exchange is complete
type DHCompleteEvent struct {
	ChatID    int64 `json:"chat_id"`
	Timestamp int64 `json:"timestamp"`
}

// MessageEvent data
type MessageEvent struct {
	ChatID    int64  `json:"chat_id"`
	MessageID int64  `json:"message_id"`
	SenderID  int64  `json:"sender_id"`
	Action    string `json:"action"` // "new"
	Timestamp int64  `json:"timestamp"`
}
