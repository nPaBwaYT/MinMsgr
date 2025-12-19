package chat

import (
	"context"
	"encoding/hex"
	"errors"
	"log"
	"time"

	"MinMsgr/server/internal/pkg/crypto"
	"MinMsgr/server/internal/protocol"
	"MinMsgr/server/internal/storage"
)

var (
	ErrChatNotFound     = errors.New("chat not found")
	ErrUserNotInChat    = errors.New("user not in chat")
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
	ErrNotChatCreator   = errors.New("only chat creator can close the chat")
)

type Service struct {
	store            *storage.DB
	broadcastHandler func(event interface{})
}

func NewService(store *storage.DB) *Service {
	return &Service{
		store: store,
	}
}

// SetBroadcastHandler sets the callback for broadcasting events
func (s *Service) SetBroadcastHandler(handler func(event interface{})) {
	s.broadcastHandler = handler
}

// GetStore returns the underlying storage instance
func (s *Service) GetStore() *storage.DB {
	return s.store
}

func (s *Service) CreateChat(ctx context.Context, req *protocol.ChatCreateRequest) (*protocol.ChatResponse, error) {
	// Validate users don't create chat with themselves
	if req.User1ID == req.User2ID {
		return &protocol.ChatResponse{
			Success: false,
			Error:   "cannot create chat with yourself",
		}, nil
	}

	// Validate users exist
	user1, err := s.store.GetUserByID(req.User1ID)
	if err != nil || user1 == nil {
		return &protocol.ChatResponse{
			Success: false,
			Error:   "user not found",
		}, nil
	}

	user2, err := s.store.GetUserByID(req.User2ID)
	if err != nil || user2 == nil {
		return &protocol.ChatResponse{
			Success: false,
			Error:   "other user not found",
		}, nil
	}

	// Validate users are accepted contacts
	contact, err := s.store.GetContact(req.User1ID, req.User2ID)
	if err != nil {
		return &protocol.ChatResponse{
			Success: false,
			Error:   "contact verification failed: " + err.Error(),
		}, nil
	}
	if contact == nil {
		return &protocol.ChatResponse{
			Success: false,
			Error:   "user is not in your contacts list",
		}, nil
	}
	if contact.Status != "accepted" {
		return &protocol.ChatResponse{
			Success: false,
			Error:   "contact request must be accepted before you can chat",
		}, nil
	}

	// Use global DH parameters so clients that generated keys from global params
	// will match the chat parameters. Generate global params if missing.
	pBytes, gBytes, err := s.GetGlobalDHParams(ctx)
	if err != nil {
		return nil, err
	}

	// Check if a chat already exists between these users (might be closed)
	existingChat, err := s.store.GetChatByUsers(req.User1ID, req.User2ID)
	if err != nil {
		return nil, err
	}

	var chatID int64

	// If a chat exists and is closed, reopen it instead of creating a new one
	if existingChat != nil && existingChat.Status == "closed" {
		if err := s.store.ReopenChat(existingChat.ID); err != nil {
			return nil, err
		}
		// Update algorithm/mode/padding if they changed
		if err := s.store.UpdateChatEncryption(existingChat.ID, req.Algorithm, req.Mode, req.Padding); err != nil {
			return nil, err
		}
		chatID = existingChat.ID
		log.Printf("[ChatService] Reopened closed chat with new encryption: chat_id=%d, user1_id=%d, user2_id=%d, algo=%s", chatID, req.User1ID, req.User2ID, req.Algorithm)
	} else if existingChat != nil {
		// Chat already exists and is active - cannot create or recreate with different parameters
		log.Printf("[ChatService] Active chat already exists: chat_id=%d, user1_id=%d, user2_id=%d", existingChat.ID, req.User1ID, req.User2ID)
		return &protocol.ChatResponse{
			Success: false,
			Error:   "active chat already exists with this user",
		}, nil
	} else {
		// Create new chat
		chatID, err = s.store.CreateChat(req.User1ID, req.User2ID, req.Algorithm, req.Mode, req.Padding)
		if err != nil {
			return nil, err
		}
		log.Printf("[ChatService] Created new chat: chat_id=%d, user1_id=%d, user2_id=%d", chatID, req.User1ID, req.User2ID)
	}

	// Save DH parameters (p, g) to database for both clients to use
	// Only save if they don't already exist (in case we're reopening a closed chat)
	p, _, _ := s.store.GetDHParameters(chatID)
	if p == nil {
		// Parameters don't exist yet, save them
		if err := s.store.SaveDHParameters(chatID, pBytes, gBytes); err != nil {
			return nil, err
		}
	}

	// Copy users' public keys (if any) into dh_public_keys for this chat
	// Only copy if they don't already exist for this chat
	if user1.PublicKey != nil {
		existing, _ := s.store.GetDHPublicKey(chatID, req.User1ID)
		if existing == nil {
			// Key doesn't exist, save it
			if err := s.store.SaveDHPublicKey(chatID, req.User1ID, user1.PublicKey); err != nil {
				return nil, err
			}
		}
	}
	if user2.PublicKey != nil {
		existing, _ := s.store.GetDHPublicKey(chatID, req.User2ID)
		if existing == nil {
			// Key doesn't exist, save it
			if err := s.store.SaveDHPublicKey(chatID, req.User2ID, user2.PublicKey); err != nil {
				return nil, err
			}
		}
	}

	// Broadcast chat creation event to both users
	if s.broadcastHandler != nil {
		chatEvent := &protocol.WebSocketEvent{
			Type:      "chat_created",
			Timestamp: time.Now().Unix(),
		}
		// Use snake_case map for JSON payload to match client expectations
		data := map[string]interface{}{
			"chat_id":   chatID,
			"user1_id":  req.User1ID,
			"user2_id":  req.User2ID,
			"action":    "created",
			"timestamp": time.Now().Unix(),
		}
		// Send to user1
		chatEvent.UserID = req.User1ID
		chatEvent.Data = data
		s.broadcastHandler(chatEvent)
		// Send to user2
		chatEvent.UserID = req.User2ID
		chatEvent.Data = data
		s.broadcastHandler(chatEvent)
	}

	return &protocol.ChatResponse{
		Success:   true,
		ChatID:    chatID,
		User1ID:   req.User1ID,
		User2ID:   req.User2ID,
		Algorithm: req.Algorithm,
		Mode:      req.Mode,
		Padding:   req.Padding,
		CreatedAt: time.Now().String(),
	}, nil
}

func (s *Service) GetUserChats(ctx context.Context, userID int64) (*protocol.GetUserChatsResponse, error) {
	chats, err := s.store.ListUserChats(userID)
	if err != nil {
		return nil, err
	}

	var protocolChats []*protocol.Chat
	for _, chat := range chats {
		protocolChats = append(protocolChats, &protocol.Chat{
			ID:        chat.ID,
			User1ID:   chat.User1ID,
			User2ID:   chat.User2ID,
			Algorithm: chat.Algorithm,
			Mode:      chat.Mode,
			Padding:   chat.Padding,
			CreatedAt: chat.CreatedAt,
		})
	}

	return &protocol.GetUserChatsResponse{
		Chats: protocolChats,
	}, nil
}

func (s *Service) JoinChat(ctx context.Context, chatID, userID int64) (*protocol.ChatResponse, error) {
	// Validate chat exists and user is participant
	chat, err := s.store.GetChat(chatID)
	if err != nil {
		return &protocol.ChatResponse{Success: false, Error: err.Error()}, nil
	}
	if chat == nil {
		return &protocol.ChatResponse{Success: false, Error: "chat not found"}, nil
	}
	if chat.User1ID != userID && chat.User2ID != userID {
		return &protocol.ChatResponse{Success: false, Error: "user not in chat"}, nil
	}

	// Broadcast a chat_joined event to the other participant so their UI can update
	if s.broadcastHandler != nil {
		otherUserID := chat.User2ID
		if chat.User1ID != userID {
			otherUserID = chat.User1ID
		}

		data := map[string]interface{}{
			"chat_id":   chatID,
			"user_id":   userID,
			"action":    "joined",
			"timestamp": time.Now().Unix(),
		}

		evt := &protocol.WebSocketEvent{
			Type:      "chat_joined",
			UserID:    otherUserID,
			Timestamp: time.Now().Unix(),
			Data:      data,
		}
		s.broadcastHandler(evt)
	}

	return &protocol.ChatResponse{Success: true}, nil
}

func (s *Service) LeaveChat(ctx context.Context, chatID, userID int64) (*protocol.ChatResponse, error) {
	// Validate chat exists and user is participant
	chat, err := s.store.GetChat(chatID)
	if err != nil {
		return &protocol.ChatResponse{Success: false, Error: err.Error()}, nil
	}
	if chat == nil {
		return &protocol.ChatResponse{Success: false, Error: "chat not found"}, nil
	}
	if chat.User1ID != userID && chat.User2ID != userID {
		return &protocol.ChatResponse{Success: false, Error: "user not in chat"}, nil
	}

	// Broadcast a chat_left event to the other participant
	if s.broadcastHandler != nil {
		otherUserID := chat.User2ID
		if chat.User1ID != userID {
			otherUserID = chat.User1ID
		}

		data := map[string]interface{}{
			"chat_id":   chatID,
			"user_id":   userID,
			"action":    "left",
			"timestamp": time.Now().Unix(),
		}

		evt := &protocol.WebSocketEvent{
			Type:      "chat_left",
			UserID:    otherUserID,
			Timestamp: time.Now().Unix(),
			Data:      data,
		}
		s.broadcastHandler(evt)
	}

	return &protocol.ChatResponse{Success: true}, nil
}

func (s *Service) CloseChat(ctx context.Context, chatID, userID int64) (*protocol.ChatResponse, error) {
	// Get the chat first
	chat, err := s.store.GetChat(chatID)
	if err != nil {
		return &protocol.ChatResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}
	if chat == nil {
		return &protocol.ChatResponse{
			Success: false,
			Error:   "chat not found",
		}, nil
	}

	// Verify user is a participant (user1 or user2)
	if chat.User1ID != userID && chat.User2ID != userID {
		return &protocol.ChatResponse{
			Success: false,
			Error:   "user not in chat",
		}, nil
	}

	// Delete all messages for this chat first
	err = s.store.DeleteChatMessages(chatID)
	if err != nil {
		log.Printf("[Chat] Warning: failed to delete messages for chat %d: %v", chatID, err)
		// Continue with closing even if message deletion fails
	} else {
		log.Printf("[Chat] Deleted messages for chat %d", chatID)
	}

	// Update chat status to closed
	err = s.store.CloseChat(chatID)
	if err != nil {
		return &protocol.ChatResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}
	// Chat closed event published via WebSocket broadcast

	return &protocol.ChatResponse{Success: true}, nil
}

// GetGlobalDHParams returns global p and g; if not present, generates and saves them
func (s *Service) GetGlobalDHParams(ctx context.Context) ([]byte, []byte, error) {
	p, g, err := s.store.GetGlobalDHParameters()
	if err != nil {
		return nil, nil, err
	}
	if p != nil && g != nil {
		return p, g, nil
	}

	// Generate new global parameters
	dh, err := crypto.NewDiffieHellman(2048)
	if err != nil {
		return nil, nil, err
	}

	if err := s.store.SaveGlobalDHParameters(dh.GetPrime(), dh.GetGenerator()); err != nil {
		return nil, nil, err
	}

	return dh.GetPrime(), dh.GetGenerator(), nil
}

// DH Key Exchange Methods
// InitiateDHExchange returns p, g, and other user's public key (if available)
func (s *Service) InitiateDHExchange(ctx context.Context, chatID, userID int64) (map[string]string, error) {
	// Get chat to validate user is in it
	chat, err := s.store.GetChat(chatID)
	if err != nil {
		return nil, err
	}
	if chat == nil {
		return nil, ErrChatNotFound
	}
	if chat.User1ID != userID && chat.User2ID != userID {
		return nil, ErrUserNotInChat
	}

	// Get DH parameters (p and g) from database
	p, g, err := s.store.GetDHParameters(chatID)
	if err != nil {
		return nil, err
	}
	if p == nil || g == nil {
		return nil, errors.New("DH parameters not found for this chat")
	}

	// Get other user's public key if available
	otherUserID := chat.User2ID
	if chat.User1ID != userID {
		otherUserID = chat.User1ID
	}

	otherUserPublicKey, err := s.store.GetDHPublicKey(chatID, otherUserID)
	if err != nil {
		return nil, err
	}

	result := map[string]string{
		"p": hex.EncodeToString(p),
		"g": hex.EncodeToString(g),
	}

	// Include other user's public key if it's available
	if otherUserPublicKey != nil {
		result["other_user_public_key"] = hex.EncodeToString(otherUserPublicKey)
	}

	return result, nil
}

// StoreDHPublicKey stores a user's public key for DH exchange
func (s *Service) StoreDHPublicKey(ctx context.Context, chatID, userID int64, publicKeyHex string) error {
	// Validate chat exists and user is in it
	chat, err := s.store.GetChat(chatID)
	if err != nil {
		return err
	}
	if chat == nil {
		return ErrChatNotFound
	}
	if chat.User1ID != userID && chat.User2ID != userID {
		return ErrUserNotInChat
	}

	// Decode public key
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return err
	}

	// Store in database
	if err := s.store.SaveDHPublicKey(chatID, userID, publicKeyBytes); err != nil {
		return err
	}

	// Broadcast public key received event to other user
	if s.broadcastHandler != nil {
		otherUserID := chat.User2ID
		if chat.User1ID != userID {
			otherUserID = chat.User1ID
		}

		// Use snake_case map for payload
		data := map[string]interface{}{
			"chat_id":    chatID,
			"user_id":    userID,
			"public_key": publicKeyHex,
			"timestamp":  time.Now().Unix(),
		}

		event := &protocol.WebSocketEvent{
			Type:      "dh_public_key_received",
			UserID:    otherUserID,
			Timestamp: time.Now().Unix(),
			Data:      data,
		}
		s.broadcastHandler(event)
	}

	return nil
}

// CompleteDHExchange just stores the public key (shared secret computed by client)
func (s *Service) CompleteDHExchange(ctx context.Context, chatID, userID int64, clientPublicKeyHex string) error {
	return s.StoreDHPublicKey(ctx, chatID, userID, clientPublicKeyHex)
}
