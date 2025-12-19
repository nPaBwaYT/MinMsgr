package contact

import (
	"context"
	"errors"
	"log"
	"time"

	"MinMsgr/server/internal/protocol"
	"MinMsgr/server/internal/storage"
)

var (
	ErrContactNotFound = errors.New("contact not found")
	ErrInvalidAction   = errors.New("invalid action")
	ErrSelfContact     = errors.New("cannot add yourself as contact")
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

func (s *Service) ProcessContactRequest(ctx context.Context, req *protocol.ContactRequest) (*protocol.ContactResponse, error) {
	if req.UserID == req.ContactID {
		return &protocol.ContactResponse{
			Success: false,
			Error:   ErrSelfContact.Error(),
		}, nil
	}

	switch req.Action {
	case "add":
		// Check if contact already exists
		contact, err := s.store.GetContact(req.UserID, req.ContactID)
		if err != nil {
			return &protocol.ContactResponse{
				Success: false,
				Error:   err.Error(),
			}, nil
		}
		if contact != nil {
			return &protocol.ContactResponse{
				Success: false,
				Error:   "Contact already exists",
			}, nil
		}
		// Add pending contact relationship
		// Note: AddContact normalizes IDs (smaller user_id → user1_id, larger → user2_id)
		// Store the ORIGINAL requester (req.UserID) as the initiator
		_, err = s.store.AddContact(req.UserID, req.ContactID, "pending")
		if err != nil {
			return &protocol.ContactResponse{
				Success: false,
				Error:   err.Error(),
			}, nil
		}
		// Log for debugging
		log.Printf("[Contact] User %d sent request to user %d", req.UserID, req.ContactID)

	case "accept":
		// Get existing contact and update status
		contact, err := s.store.GetContact(req.UserID, req.ContactID)
		if err != nil {
			return &protocol.ContactResponse{
				Success: false,
				Error:   err.Error(),
			}, nil
		}
		if contact == nil {
			return &protocol.ContactResponse{
				Success: false,
				Error:   ErrContactNotFound.Error(),
			}, nil
		}
		// Verify this is a pending request sent to the current user (check requester_id)
		if contact.Status != "pending" {
			return &protocol.ContactResponse{
				Success: false,
				Error:   "Contact request is not pending",
			}, nil
		}
		// Only the person who received the request (not the requester) can accept
		if contact.RequesterID == req.UserID {
			return &protocol.ContactResponse{
				Success: false,
				Error:   "You can only accept contact requests sent to you",
			}, nil
		}
		err = s.store.UpdateContactStatus(contact.ID, "accepted")
		if err != nil {
			return &protocol.ContactResponse{
				Success: false,
				Error:   err.Error(),
			}, nil
		}
		log.Printf("[Contact] User %d accepted request from user %d", req.UserID, contact.RequesterID)

	case "reject", "remove":
		// Get and delete the contact relationship
		contact, err := s.store.GetContact(req.UserID, req.ContactID)
		if err != nil {
			return &protocol.ContactResponse{
				Success: false,
				Error:   err.Error(),
			}, nil
		}
		if contact == nil {
			return &protocol.ContactResponse{
				Success: false,
				Error:   ErrContactNotFound.Error(),
			}, nil
		}
		// Verify this is a pending request sent to the current user (check requester_id)
		if req.Action == "reject" && contact.Status != "pending" {
			return &protocol.ContactResponse{
				Success: false,
				Error:   "Can only reject pending contact requests",
			}, nil
		}
		// Only the person who received the request (not the requester) can reject
		if req.Action == "reject" && contact.RequesterID == req.UserID {
			return &protocol.ContactResponse{
				Success: false,
				Error:   "You can only reject contact requests sent to you",
			}, nil
		}
		err = s.store.DeleteContact(contact.ID)
		if err != nil {
			return &protocol.ContactResponse{
				Success: false,
				Error:   err.Error(),
			}, nil
		}
		log.Printf("[Contact] User %d %sed contact with user %d", req.UserID, req.Action, contact.RequesterID)

	default:
		return &protocol.ContactResponse{
			Success: false,
			Error:   ErrInvalidAction.Error(),
		}, nil
	}

	// Broadcast WebSocket event if handler is set
	if s.broadcastHandler != nil {
		var action string
		var eventType string
		switch req.Action {
		case "accept":
			action = "accepted"
			eventType = "contact_accepted"
		case "reject":
			action = "rejected"
			eventType = "contact_rejected"
		case "remove":
			action = "removed"
			eventType = "contact_removed"
		default:
			action = req.Action
			eventType = "contact_request"
		}

		// Get username of the user initiating the action
		user, err := s.store.GetUserByID(req.UserID)
		if err != nil {
			log.Printf("Failed to get user info: %v", err)
		}

		// For "add" action: send to both requester and recipient so they both see the pending request
		// For other actions: send to both users so they both see the updated status
		targetUsers := []int64{req.ContactID, req.UserID}

		for _, targetUserID := range targetUsers {
			wsEvent := &protocol.WebSocketEvent{
				Type:      eventType,
				UserID:    targetUserID,
				Timestamp: time.Now().Unix(),
				Data: protocol.ContactRequestEvent{
					ContactID: req.ContactID,
					UserID:    req.UserID,
					Username:  user.Username,
					Status:    "pending",
					Action:    action,
				},
			}
			log.Printf("[Contact] Broadcasting %s to user %d (action from user %d)", eventType, targetUserID, req.UserID)
			s.broadcastHandler(wsEvent)
		}
	}

	return &protocol.ContactResponse{Success: true}, nil
}

func (s *Service) GetContacts(ctx context.Context, userID int64) ([]*storage.Contact, error) {
	// Get accepted contacts
	return s.store.ListUserContacts(userID, "accepted")
}

// GetPendingRequests returns all pending contact requests for a user
// Previously this filtered to only incoming requests which hid outgoing
// requests from the sender. Return all pending records and let the
// client compute direction using the `requester_id` field.
func (s *Service) GetPendingRequests(ctx context.Context, userID int64) ([]*storage.Contact, error) {
	return s.store.ListUserContacts(userID, "pending")
}
