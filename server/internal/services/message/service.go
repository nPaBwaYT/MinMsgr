package message

import (
	"MinMsgr/server/internal/protocol"
	"MinMsgr/server/internal/storage"
	"context"
	"fmt"
	"log"
	"sync"
)

type Service struct {
	store            *storage.DB
	broadcastHandler func(event interface{})
	// In-memory message buffer (temporary storage until delivered)
	messageBuffer map[int64][]*protocol.EncryptedMessage
	bufferMutex   sync.RWMutex
}

func NewService(store *storage.DB) *Service {
	return &Service{
		store:         store,
		messageBuffer: make(map[int64][]*protocol.EncryptedMessage),
	}
}

// SetBroadcastHandler sets the callback for broadcasting events
func (s *Service) SetBroadcastHandler(handler func(event interface{})) {
	s.broadcastHandler = handler
}

func (s *Service) ProcessMessage(ctx context.Context, msg *protocol.EncryptedMessage) error {
	// Log message routing info
	ciphertextHex := ""
	if len(msg.Ciphertext) > 0 {
		// Convert ciphertext to hex and show first 32 characters
		ciphertextHex = fmt.Sprintf("%x", msg.Ciphertext)
		if len(ciphertextHex) > 32 {
			ciphertextHex = ciphertextHex[:32]
		}
	}
	log.Printf("[MessageService] Routing message: chat_id=%d, sender_id=%d, ciphertext_start=%s",
		msg.ChatID, msg.SenderID, ciphertextHex)

	// Get the chat to find the other user
	chat, err := s.store.GetChat(msg.ChatID)
	if err != nil || chat == nil {
		log.Printf("[MessageService] Failed to get chat: %v", err)
		return err
	}

	// Save message to database
	messageID, err := s.store.SaveMessage(msg.ChatID, msg.SenderID, msg.Ciphertext, msg.IV, msg.FileName, msg.MimeType)
	if err != nil {
		log.Printf("[MessageService] Failed to save message: %v", err)
		return err
	}

	// Determine recipient user ID (the other participant in the chat)
	var recipientUserID int64
	if chat.User1ID == msg.SenderID {
		recipientUserID = chat.User2ID
	} else {
		recipientUserID = chat.User1ID
	}

	// Broadcast WebSocket event to BOTH participants
	if s.broadcastHandler != nil {
		// Convert ciphertext and IV to hex strings for transmission
		ciphertextHex := fmt.Sprintf("%x", msg.Ciphertext)
		ivHex := fmt.Sprintf("%x", msg.IV)

		data := map[string]interface{}{
			"id":         messageID,
			"chat_id":    msg.ChatID,
			"sender_id":  msg.SenderID,
			"ciphertext": ciphertextHex,
			"iv":         ivHex,
			"action":     "new",
			"timestamp":  msg.Timestamp,
		}

		// include optional file metadata when present
		if msg.FileName != "" {
			data["file_name"] = msg.FileName
		}
		if msg.MimeType != "" {
			data["mime_type"] = msg.MimeType
		}

		// Send to RECIPIENT
		wsEvent := &protocol.WebSocketEvent{
			Type:      "message_received",
			UserID:    recipientUserID,
			Timestamp: msg.Timestamp,
			Data:      data,
		}
		log.Printf("[MessageService] Broadcasting to RECIPIENT (UserID=%d) message (id=%d, chat_id=%d)", recipientUserID, messageID, msg.ChatID)
		s.broadcastHandler(wsEvent)

		// Send to SENDER (so they get the real ID for their message)
		wsEvent = &protocol.WebSocketEvent{
			Type:      "message_received",
			UserID:    msg.SenderID,
			Timestamp: msg.Timestamp,
			Data:      data,
		}
		log.Printf("[MessageService] Broadcasting to SENDER (UserID=%d) message (id=%d, chat_id=%d)", msg.SenderID, messageID, msg.ChatID)
		s.broadcastHandler(wsEvent)
	}

	return nil
}

func (s *Service) GetChatMessages(ctx context.Context, chatID int64, limit, offset int) ([]*protocol.EncryptedMessage, error) {
	// Get messages from database
	messages, err := s.store.GetChatMessages(chatID, limit)
	if err != nil {
		return nil, err
	}
	if len(messages) == 0 {
		return make([]*protocol.EncryptedMessage, 0), nil
	}

	// Convert storage messages to protocol messages
	result := make([]*protocol.EncryptedMessage, 0, len(messages))
	for _, m := range messages {
		msg := &protocol.EncryptedMessage{
			ID:         m.ID,
			ChatID:     m.ChatID,
			SenderID:   m.SenderID,
			Ciphertext: m.Ciphertext,
			IV:         m.IV,
			Timestamp:  m.CreatedAt,
			FileName:   m.FileName,
			MimeType:   m.MimeType,
		}
		result = append(result, msg)
	}

	return result, nil
}

// DeleteChatMessages removes messages for a chat (called when chat is closed)
func (s *Service) DeleteChatMessages(chatID int64) {
	s.bufferMutex.Lock()
	delete(s.messageBuffer, chatID)
	s.bufferMutex.Unlock()
}
