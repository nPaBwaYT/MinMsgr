package storage

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

// DB wraps the database connection and provides query methods
type DB struct {
	conn *sql.DB
}

// Config contains database connection configuration
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
}

// New creates a new database connection
func New(cfg Config) (*DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database, cfg.SSLMode,
	)

	conn, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	// Test the connection
	if err := conn.Ping(); err != nil {
		return nil, err
	}

	return &DB{conn: conn}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// InitSchema creates all database tables
func (db *DB) InitSchema() error {
	schema := `
	-- Users table
	CREATE TABLE IF NOT EXISTS users (
		id BIGSERIAL PRIMARY KEY,
		username VARCHAR(255) UNIQUE NOT NULL,
		hashed_password VARCHAR(255) NOT NULL,
		public_key BYTEA,
		encrypted_private_key BYTEA,
		created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
		updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
	);

	-- Contacts table
	CREATE TABLE IF NOT EXISTS contacts (
		id BIGSERIAL PRIMARY KEY,
		user1_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		user2_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		requester_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		status VARCHAR(50) NOT NULL DEFAULT 'pending',
		created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
		updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
		UNIQUE(user1_id, user2_id),
		CHECK(user1_id < user2_id)
	);

	-- Chats table
	CREATE TABLE IF NOT EXISTS chats (
		id BIGSERIAL PRIMARY KEY,
		user1_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		user2_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		algorithm VARCHAR(50) NOT NULL,
		mode VARCHAR(50) NOT NULL,
		padding VARCHAR(50) NOT NULL,
		status VARCHAR(50) NOT NULL DEFAULT 'active',
		created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
		closed_at BIGINT,
		updated_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
		UNIQUE(user1_id, user2_id)
	);

	-- DH Parameters table (stores p, g for each chat)
	CREATE TABLE IF NOT EXISTS dh_parameters (
		id BIGSERIAL PRIMARY KEY,
		chat_id BIGINT NOT NULL UNIQUE REFERENCES chats(id) ON DELETE CASCADE,
		p BYTEA NOT NULL,
		g BYTEA NOT NULL,
		created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
	);

	-- Global DH parameters (single row)
	CREATE TABLE IF NOT EXISTS dh_globals (
		id BIGSERIAL PRIMARY KEY,
		p BYTEA NOT NULL,
		g BYTEA NOT NULL,
		created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
	);

	-- DH Public Keys table (stores A and B public keys)
	CREATE TABLE IF NOT EXISTS dh_public_keys (
		id BIGSERIAL PRIMARY KEY,
		chat_id BIGINT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
		user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		public_key BYTEA NOT NULL,
		created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT,
		UNIQUE(chat_id, user_id)
	);

	-- Messages table
	CREATE TABLE IF NOT EXISTS messages (
		id BIGSERIAL PRIMARY KEY,
		chat_id BIGINT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
		sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		ciphertext BYTEA NOT NULL,
		created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);
	CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id);
	CREATE INDEX IF NOT EXISTS idx_chats_user1_id ON chats(user1_id);
	CREATE INDEX IF NOT EXISTS idx_chats_user2_id ON chats(user2_id);
	CREATE INDEX IF NOT EXISTS idx_contacts_user1_id ON contacts(user1_id);
	CREATE INDEX IF NOT EXISTS idx_contacts_user2_id ON contacts(user2_id);
	`

	_, err := db.conn.Exec(schema)
	if err != nil {
		return err
	}

	// Ensure any added columns from migrations exist (for running against older DBs)
	alterStmts := []string{
		"ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key BYTEA",
		"ALTER TABLE users ADD COLUMN IF NOT EXISTS encrypted_private_key BYTEA",
		"ALTER TABLE dh_parameters ADD COLUMN IF NOT EXISTS p BYTEA",
		"ALTER TABLE dh_parameters ADD COLUMN IF NOT EXISTS g BYTEA",
		"ALTER TABLE dh_parameters DROP COLUMN IF EXISTS public_key",
		"ALTER TABLE dh_parameters ADD COLUMN IF NOT EXISTS user_id BIGINT",
		"ALTER TABLE dh_parameters ALTER COLUMN user_id DROP NOT NULL",
		"ALTER TABLE contacts ADD COLUMN IF NOT EXISTS requester_id BIGINT",
		"UPDATE contacts SET requester_id = user1_id WHERE requester_id IS NULL",
		"ALTER TABLE messages ADD COLUMN IF NOT EXISTS iv BYTEA",
		"ALTER TABLE messages ADD COLUMN IF NOT EXISTS file_name VARCHAR(255)",
		"ALTER TABLE messages ADD COLUMN IF NOT EXISTS mime_type VARCHAR(100)",
		`CREATE TABLE IF NOT EXISTS session_keys (
			id BIGSERIAL PRIMARY KEY,
			chat_id BIGINT NOT NULL UNIQUE REFERENCES chats(id) ON DELETE CASCADE,
			session_key BYTEA NOT NULL,
			iv BYTEA NOT NULL,
			created_at BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT
		)`,
	}

	for _, s := range alterStmts {
		if _, err := db.conn.Exec(s); err != nil {
			return err
		}
	}

	return nil
}

// User operations

// CreateUser creates a new user with hashed password
func (db *DB) CreateUser(username, hashedPassword string) (int64, error) {
	var id int64
	err := db.conn.QueryRow(
		"INSERT INTO users (username, hashed_password, public_key, encrypted_private_key) VALUES ($1, $2, $3, $4) RETURNING id",
		username, hashedPassword, nil, nil,
	).Scan(&id)
	return id, err
}

// GetUserByID retrieves a user by ID
func (db *DB) GetUserByID(userID int64) (*User, error) {
	user := &User{}
	err := db.conn.QueryRow(
		"SELECT id, username, hashed_password, public_key, encrypted_private_key, created_at FROM users WHERE id = $1",
		userID,
	).Scan(&user.ID, &user.Username, &user.HashedPassword, &user.PublicKey, &user.EncryptedPrivateKey, &user.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

// GetUserByUsername retrieves a user by username
func (db *DB) GetUserByUsername(username string) (*User, error) {
	user := &User{}
	err := db.conn.QueryRow(
		"SELECT id, username, hashed_password, public_key, encrypted_private_key, created_at FROM users WHERE username = $1",
		username,
	).Scan(&user.ID, &user.Username, &user.HashedPassword, &user.PublicKey, &user.EncryptedPrivateKey, &user.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return user, err
}

// Contact operations

// AddContact creates a contact relationship between two users with requester ID
func (db *DB) AddContact(userID1, userID2 int64, status string) (int64, error) {
	// Ensure consistent ordering and track the requester
	requesterID := userID1
	if userID1 > userID2 {
		userID1, userID2 = userID2, userID1
	}

	var id int64
	err := db.conn.QueryRow(
		"INSERT INTO contacts (user1_id, user2_id, requester_id, status) VALUES ($1, $2, $3, $4) RETURNING id",
		userID1, userID2, requesterID, status,
	).Scan(&id)
	return id, err
}

// GetContact retrieves a contact relationship
func (db *DB) GetContact(userID1, userID2 int64) (*Contact, error) {
	if userID1 > userID2 {
		userID1, userID2 = userID2, userID1
	}

	contact := &Contact{}
	err := db.conn.QueryRow(
		"SELECT id, user1_id, user2_id, requester_id, status, created_at FROM contacts WHERE user1_id = $1 AND user2_id = $2",
		userID1, userID2,
	).Scan(&contact.ID, &contact.User1ID, &contact.User2ID, &contact.RequesterID, &contact.Status, &contact.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return contact, err
}

// UpdateContactStatus updates the status of a contact relationship
func (db *DB) UpdateContactStatus(contactID int64, status string) error {
	_, err := db.conn.Exec(
		"UPDATE contacts SET status = $1, updated_at = $2 WHERE id = $3",
		status, time.Now().Unix(), contactID,
	)
	return err
}

// ListUserContacts lists all contacts of a user with given status
func (db *DB) ListUserContacts(userID int64, status string) ([]*Contact, error) {
	rows, err := db.conn.Query(
		"SELECT id, user1_id, user2_id, requester_id, status, created_at FROM contacts WHERE (user1_id = $1 OR user2_id = $1) AND status = $2",
		userID, status,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []*Contact
	for rows.Next() {
		contact := &Contact{}
		err := rows.Scan(&contact.ID, &contact.User1ID, &contact.User2ID, &contact.RequesterID, &contact.Status, &contact.CreatedAt)
		if err != nil {
			return nil, err
		}
		contacts = append(contacts, contact)
	}

	return contacts, rows.Err()
}

// DeleteContact deletes a contact relationship
func (db *DB) DeleteContact(contactID int64) error {
	_, err := db.conn.Exec("DELETE FROM contacts WHERE id = $1", contactID)
	return err
}

// Chat operations

// CreateChat creates a new encrypted chat
func (db *DB) CreateChat(userID1, userID2 int64, algorithm, mode, padding string) (int64, error) {
	if userID1 > userID2 {
		userID1, userID2 = userID2, userID1
	}

	var id int64
	err := db.conn.QueryRow(
		"INSERT INTO chats (user1_id, user2_id, algorithm, mode, padding) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		userID1, userID2, algorithm, mode, padding,
	).Scan(&id)
	return id, err
}

// UpdateChatEncryption updates the encryption algorithm, mode, and padding for a chat
func (db *DB) UpdateChatEncryption(chatID int64, algorithm, mode, padding string) error {
	_, err := db.conn.Exec(
		"UPDATE chats SET algorithm = $1, mode = $2, padding = $3, updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT WHERE id = $4",
		algorithm, mode, padding, chatID,
	)
	return err
}

// GetChat retrieves a chat by ID
func (db *DB) GetChat(chatID int64) (*Chat, error) {
	chat := &Chat{}
	err := db.conn.QueryRow(
		"SELECT id, user1_id, user2_id, algorithm, mode, padding, status, created_at, closed_at FROM chats WHERE id = $1",
		chatID,
	).Scan(&chat.ID, &chat.User1ID, &chat.User2ID, &chat.Algorithm, &chat.Mode, &chat.Padding, &chat.Status, &chat.CreatedAt, &chat.ClosedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return chat, err
}

// ListUserChats lists all active chats for a user
func (db *DB) ListUserChats(userID int64) ([]*Chat, error) {
	rows, err := db.conn.Query(
		"SELECT id, user1_id, user2_id, algorithm, mode, padding, status, created_at FROM chats WHERE (user1_id = $1 OR user2_id = $1) AND status = 'active' ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var chats []*Chat
	for rows.Next() {
		chat := &Chat{}
		err := rows.Scan(&chat.ID, &chat.User1ID, &chat.User2ID, &chat.Algorithm, &chat.Mode, &chat.Padding, &chat.Status, &chat.CreatedAt)
		if err != nil {
			return nil, err
		}
		chats = append(chats, chat)
	}

	return chats, rows.Err()
}

// GetChatByUsers retrieves an existing chat between two users (any status)
func (db *DB) GetChatByUsers(userID1, userID2 int64) (*Chat, error) {
	if userID1 > userID2 {
		userID1, userID2 = userID2, userID1
	}

	chat := &Chat{}
	err := db.conn.QueryRow(
		"SELECT id, user1_id, user2_id, algorithm, mode, padding, status, created_at, closed_at FROM chats WHERE user1_id = $1 AND user2_id = $2",
		userID1, userID2,
	).Scan(&chat.ID, &chat.User1ID, &chat.User2ID, &chat.Algorithm, &chat.Mode, &chat.Padding, &chat.Status, &chat.CreatedAt, &chat.ClosedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return chat, err
}

// ReopenChat reopens a closed chat (set status to 'active' and clear closed_at)
func (db *DB) ReopenChat(chatID int64) error {
	_, err := db.conn.Exec(
		"UPDATE chats SET status = 'active', closed_at = NULL, updated_at = $1 WHERE id = $2 AND status = 'closed'",
		time.Now().Unix(), chatID,
	)
	return err
}

// CloseChat closes an active chat
func (db *DB) CloseChat(chatID int64) error {
	_, err := db.conn.Exec(
		"UPDATE chats SET status = 'closed', closed_at = $1, updated_at = $1 WHERE id = $2",
		time.Now().Unix(), chatID,
	)
	return err
}

// Message operations

// SaveMessage saves an encrypted message with IV and optional metadata
func (db *DB) SaveMessage(chatID, senderID int64, ciphertext []byte, iv []byte, fileName string, mimeType string) (int64, error) {
	var id int64
	err := db.conn.QueryRow(
		"INSERT INTO messages (chat_id, sender_id, ciphertext, iv, file_name, mime_type) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		chatID, senderID, ciphertext, iv, fileName, mimeType,
	).Scan(&id)
	return id, err
}

// DeleteChatMessages deletes all messages for a specific chat
func (db *DB) DeleteChatMessages(chatID int64) error {
	result, err := db.conn.Exec("DELETE FROM messages WHERE chat_id = $1", chatID)
	if err != nil {
		return err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	fmt.Printf("[Storage] Deleted %d messages for chat %d\n", rowsAffected, chatID)
	return nil
}

// GetChatMessages retrieves messages from a chat (with optional limit)
func (db *DB) GetChatMessages(chatID int64, limit int) ([]*Message, error) {
	rows, err := db.conn.Query(
		"SELECT id, chat_id, sender_id, ciphertext, COALESCE(iv, ''::bytea), COALESCE(file_name, ''), COALESCE(mime_type, ''), created_at FROM messages WHERE chat_id = $1 ORDER BY created_at ASC LIMIT $2",
		chatID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		msg := &Message{}
		err := rows.Scan(&msg.ID, &msg.ChatID, &msg.SenderID, &msg.Ciphertext, &msg.IV, &msg.FileName, &msg.MimeType, &msg.CreatedAt)
		if err != nil {
			return nil, err
		}
		msg.Timestamp = msg.CreatedAt
		messages = append(messages, msg)
	}

	return messages, rows.Err()
}

// Session key operations

// SaveSessionKey saves the session key for a chat
func (db *DB) SaveSessionKey(chatID int64, sessionKey, iv []byte) error {
	_, err := db.conn.Exec(
		"INSERT INTO session_keys (chat_id, session_key, iv) VALUES ($1, $2, $3) ON CONFLICT (chat_id) DO UPDATE SET session_key = $2, iv = $3",
		chatID, sessionKey, iv,
	)
	return err
}

// GetSessionKey retrieves the session key for a chat
func (db *DB) GetSessionKey(chatID int64) (*SessionKey, error) {
	sk := &SessionKey{}
	err := db.conn.QueryRow(
		"SELECT chat_id, session_key, iv, created_at FROM session_keys WHERE chat_id = $1",
		chatID,
	).Scan(&sk.ChatID, &sk.Key, &sk.IV, &sk.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return sk, err
}

// DH parameters and public keys

// SaveDHParameters saves the DH parameters (p, g) for a chat
func (db *DB) SaveDHParameters(chatID int64, p, g []byte) error {
	_, err := db.conn.Exec(
		"INSERT INTO dh_parameters (chat_id, p, g) VALUES ($1, $2, $3)",
		chatID, p, g,
	)
	return err
}

// SaveGlobalDHParameters saves the global DH parameters (p, g)
func (db *DB) SaveGlobalDHParameters(p, g []byte) error {
	// Upsert into single-row table
	_, err := db.conn.Exec(
		"INSERT INTO dh_globals (p, g) VALUES ($1, $2)",
		p, g,
	)
	return err
}

// GetGlobalDHParameters retrieves global DH params (p, g). Returns nil,nil,nil if not found
func (db *DB) GetGlobalDHParameters() (p, g []byte, err error) {
	err = db.conn.QueryRow(
		"SELECT p, g FROM dh_globals ORDER BY id LIMIT 1",
	).Scan(&p, &g)

	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	return p, g, err
}

// GetDHParameters retrieves the DH parameters (p, g) for a chat
func (db *DB) GetDHParameters(chatID int64) (p, g []byte, err error) {
	err = db.conn.QueryRow(
		"SELECT p, g FROM dh_parameters WHERE chat_id = $1",
		chatID,
	).Scan(&p, &g)

	if err == sql.ErrNoRows {
		return nil, nil, nil
	}
	return p, g, err
}

// SaveDHPublicKey saves a user's DH public key for a chat
func (db *DB) SaveDHPublicKey(chatID, userID int64, publicKey []byte) error {
	_, err := db.conn.Exec(
		"INSERT INTO dh_public_keys (chat_id, user_id, public_key) VALUES ($1, $2, $3) ON CONFLICT (chat_id, user_id) DO UPDATE SET public_key = $3",
		chatID, userID, publicKey,
	)
	return err
}

// SaveUserKeys stores a user's public key and encrypted private key
func (db *DB) SaveUserKeys(userID int64, publicKey, encryptedPrivateKey []byte) error {
	_, err := db.conn.Exec(
		"UPDATE users SET public_key = $1, encrypted_private_key = $2, updated_at = $3 WHERE id = $4",
		publicKey, encryptedPrivateKey, time.Now().Unix(), userID,
	)
	return err
}

// GetDHPublicKey retrieves a user's DH public key for a chat
func (db *DB) GetDHPublicKey(chatID, userID int64) ([]byte, error) {
	var publicKey []byte
	err := db.conn.QueryRow(
		"SELECT public_key FROM dh_public_keys WHERE chat_id = $1 AND user_id = $2",
		chatID, userID,
	).Scan(&publicKey)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return publicKey, err
}

// GetOtherUserPublicKey retrieves the other user's DH public key for a chat
func (db *DB) GetOtherUserPublicKey(chatID, userID int64) ([]byte, error) {
	var publicKey []byte
	err := db.conn.QueryRow(
		"SELECT public_key FROM dh_public_keys WHERE chat_id = $1 AND user_id != $2",
		chatID, userID,
	).Scan(&publicKey)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return publicKey, err
}

// Data types

// User represents a user in the system
// User represents a user in the system, extended with DH fields
type User struct {
	ID                  int64
	Username            string
	HashedPassword      string
	PublicKey           []byte
	EncryptedPrivateKey []byte
	CreatedAt           int64
}

// Contact represents a contact relationship
type Contact struct {
	ID          int64  `json:"id"`
	User1ID     int64  `json:"user1_id"`
	User2ID     int64  `json:"user2_id"`
	RequesterID int64  `json:"requester_id"`
	Username    string `json:"username"`
	Status      string `json:"status"`
	CreatedAt   int64  `json:"created_at"`
}

// Chat represents an encrypted chat
type Chat struct {
	ID        int64  `json:"id"`
	User1ID   int64  `json:"user1_id"`
	User2ID   int64  `json:"user2_id"`
	Algorithm string `json:"algorithm"`
	Mode      string `json:"mode"`
	Padding   string `json:"padding"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"created_at"`
	ClosedAt  *int64 `json:"closed_at,omitempty"`
}

// Message represents an encrypted message
type Message struct {
	ID         int64  `json:"id"`
	ChatID     int64  `json:"chat_id"`
	SenderID   int64  `json:"sender_id"`
	Ciphertext []byte `json:"ciphertext"`
	IV         []byte `json:"iv"`
	FileName   string `json:"file_name,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	Timestamp  int64  `json:"timestamp"`
}

// SessionKey represents a shared session key
type SessionKey struct {
	ChatID    int64
	Key       []byte
	IV        []byte
	CreatedAt int64
}
