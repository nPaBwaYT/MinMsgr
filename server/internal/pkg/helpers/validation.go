package helpers

import (
	"errors"

	"MinMsgr/server/internal/storage"
)

// ValidateUserExists checks if a user exists in the database
func ValidateUserExists(db *storage.DB, userID int64) (*storage.User, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user ID")
	}

	user, err := db.GetUserByID(userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// ValidateChatExists checks if a chat exists and user is a participant
func ValidateChatExists(db *storage.DB, chatID, userID int64) (*storage.Chat, error) {
	if chatID <= 0 {
		return nil, errors.New("invalid chat ID")
	}

	chat, err := db.GetChat(chatID)
	if err != nil {
		return nil, err
	}
	if chat == nil {
		return nil, errors.New("chat not found")
	}

	// Verify user is participant
	if chat.User1ID != userID && chat.User2ID != userID {
		return nil, errors.New("user not in chat")
	}

	return chat, nil
}

// ValidateContactExists checks if a contact relationship exists
func ValidateContactExists(db *storage.DB, userID1, userID2 int64) (*storage.Contact, error) {
	if userID1 <= 0 || userID2 <= 0 {
		return nil, errors.New("invalid user IDs")
	}

	contact, err := db.GetContact(userID1, userID2)
	if err != nil {
		return nil, err
	}
	if contact == nil {
		return nil, errors.New("contact not found")
	}

	return contact, nil
}

// GetOtherParticipant returns the other user in a two-user chat
func GetOtherParticipant(chat *storage.Chat, currentUserID int64) int64 {
	if chat.User1ID == currentUserID {
		return chat.User2ID
	}
	return chat.User1ID
}
