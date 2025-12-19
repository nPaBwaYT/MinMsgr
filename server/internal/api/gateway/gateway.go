// Gateway API implementation
package gateway

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	"MinMsgr/server/internal/protocol"
	"MinMsgr/server/internal/services/auth"
	"MinMsgr/server/internal/services/chat"
	"MinMsgr/server/internal/services/contact"
	"MinMsgr/server/internal/services/message"
)

// Server represents the API gateway
type Server struct {
	addr       string
	authSvc    *auth.Service
	contactSvc *contact.Service
	chatSvc    *chat.Service
	messageSvc *message.Service
	mu         sync.RWMutex
	clients    map[*Client]bool
	broadcast  chan interface{}
	register   chan *Client
	unregister chan *Client
}

// Client represents a connected WebSocket client
type Client struct {
	userID int64
	conn   *websocket.Conn
	send   chan interface{}
	server *Server
}

// corsMiddleware adds CORS headers to all responses
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractToken extracts the token from "Bearer <token>" format
func extractToken(authHeader string) string {
	parts := strings.Fields(authHeader)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	return parts[1]
}

// New creates a new gateway server
func New(addr string, authSvc *auth.Service, contactSvc *contact.Service, chatSvc *chat.Service, messageSvc *message.Service) *Server {
	server := &Server{
		addr:       addr,
		authSvc:    authSvc,
		contactSvc: contactSvc,
		chatSvc:    chatSvc,
		messageSvc: messageSvc,
		clients:    make(map[*Client]bool),
		broadcast:  make(chan interface{}, 1024), // Buffered channel to prevent blocking
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}

	// Set broadcast handler for all services
	broadcastHandler := func(event interface{}) {
		server.Broadcast(event)
	}
	contactSvc.SetBroadcastHandler(broadcastHandler)
	chatSvc.SetBroadcastHandler(broadcastHandler)
	messageSvc.SetBroadcastHandler(broadcastHandler)

	return server
}

// Start starts the gateway server
func (s *Server) Start() error {
	router := mux.NewRouter()

	// Root endpoint - return OK for health checks
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("MinMessanger API Server"))
	}).Methods("GET", "OPTIONS")

	// Auth endpoints
	router.HandleFunc("/api/auth/register", s.handleRegister).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/auth/login", s.handleLogin).Methods("POST", "OPTIONS")

	// Contact endpoints
	router.HandleFunc("/api/contacts", s.handleGetContacts).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/contacts/request", s.handleContactRequest).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/contacts/pending", s.handleGetPendingRequests).Methods("GET", "OPTIONS")

	// Chat endpoints - more specific routes first
	router.HandleFunc("/api/chats/create", s.handleCreateChat).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/chats", s.handleGetChats).Methods("GET", "OPTIONS")

	// Global DH params (public)
	router.HandleFunc("/api/dh/global", s.handleGetGlobalDHParams).Methods("GET", "OPTIONS")
	// User public key (stored at registration)
	router.HandleFunc("/api/users/{userID}/public-key", s.handleGetUserPublicKey).Methods("GET", "OPTIONS")
	// Authenticated user's own public key
	router.HandleFunc("/api/me/public-key", s.handleGetMyPublicKey).Methods("GET", "OPTIONS")

	router.HandleFunc("/api/chats/{chatID}/dh/init", s.handleDHInit).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/chats/{chatID}/dh/exchange", s.handleDHExchange).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/chats/{chatID}/messages", s.handleGetMessages).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/chats/{chatID}/close", s.handleCloseChat).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/chats/{chatID}/join", s.handleJoinChat).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/chats/{chatID}/leave", s.handleLeaveChat).Methods("POST", "OPTIONS")

	// Message endpoints
	router.HandleFunc("/api/messages/send", s.handleSendMessage).Methods("POST", "OPTIONS")

	// WebSocket endpoint
	router.HandleFunc("/ws", s.handleWebSocket)

	// Start hub goroutine
	go s.runHub()

	fmt.Printf("Gateway server listening on %s\n", s.addr)
	return http.ListenAndServe(s.addr, corsMiddleware(router))
}

// handleRegister handles user registration
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username            string `json:"username"`
		Password            string `json:"password"`
		PublicKey           string `json:"public_key"`
		EncryptedPrivateKey string `json:"encrypted_private_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID, encPrivHex, err := s.authSvc.Register(req.Username, req.Password, req.PublicKey, req.EncryptedPrivateKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create token
	token, err := s.authSvc.CreateToken(userID, req.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"user_id":  userID,
		"token":    token,
		"username": req.Username,
	}
	if encPrivHex != "" {
		response["encrypted_private_key"] = encPrivHex
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Public endpoint to return global DH parameters (p,g)
func (s *Server) handleGetGlobalDHParams(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	p, g, err := s.chatSvc.GetGlobalDHParams(ctx)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if p == nil || g == nil {
		http.Error(w, "DH parameters not initialized", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"p": hex.EncodeToString(p),
		"g": hex.EncodeToString(g),
	})
}

// handleGetMyPublicKey retrieves the authenticated user's public key
func (s *Server) handleGetMyPublicKey(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	pub, err := s.authSvc.GetUserPublicKey(claims.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]string{"public_key": ""}
	if pub != nil {
		resp["public_key"] = hex.EncodeToString(pub)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleGetUserPublicKey(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	_, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	uid := parseInt(vars["userID"])

	pub, err := s.authSvc.GetUserPublicKey(int64(uid))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := map[string]string{"public_key": ""}
	if pub != nil {
		resp["public_key"] = hex.EncodeToString(pub)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleLogin handles user login
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, encPrivHex, err := s.authSvc.Login(req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Parse token to get user ID
	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"user_id":               claims.UserID,
		"username":              claims.Username,
		"token":                 token,
		"encrypted_private_key": encPrivHex,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	// Try to get token from query parameter first (preferred for WebSocket)
	token := r.URL.Query().Get("token")

	// Fall back to Authorization header if not in query
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			// Remove "Bearer " prefix
			if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				token = authHeader[7:]
			}
		}
	}

	if token == "" {
		log.Println("WebSocket connection rejected: no token provided")
		conn.Close()
		return
	}

	// Validate token
	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		log.Printf("WebSocket connection rejected: invalid token - %v", err)
		conn.Close()
		return
	}

	client := &Client{
		userID: claims.UserID,
		conn:   conn,
		send:   make(chan interface{}, 256),
		server: s,
	}

	s.register <- client
	log.Printf("WebSocket client connected: user %d", claims.UserID)

	// Start reading and writing goroutines
	go client.readPump()
	go client.writePump()
}

// runHub manages all connected clients
func (s *Server) runHub() {
	for {
		select {
		case client := <-s.register:
			s.mu.Lock()
			s.clients[client] = true
			s.mu.Unlock()
			fmt.Printf("Client connected: %d\n", client.userID)

		case client := <-s.unregister:
			s.mu.Lock()
			if _, ok := s.clients[client]; ok {
				delete(s.clients, client)
				close(client.send)
			}
			s.mu.Unlock()
			fmt.Printf("Client disconnected: %d\n", client.userID)

		case message := <-s.broadcast:
			s.mu.RLock()
			// If message is a targeted WebSocketEvent with UserID != 0, send only to that user
			if wsEvent, ok := message.(*protocol.WebSocketEvent); ok && wsEvent.UserID != 0 {
				targetUserID := wsEvent.UserID
				connectedUserIDs := make([]int64, 0)
				for c := range s.clients {
					connectedUserIDs = append(connectedUserIDs, c.userID)
				}
				log.Printf("[Hub] Broadcasting targeted %s to user %d. Connected users: %v", wsEvent.Type, targetUserID, connectedUserIDs)

				sentCount := 0
				for c := range s.clients {
					if c.userID == wsEvent.UserID {
						select {
						case c.send <- message:
							sentCount++
							log.Printf("[Hub] ✓ Sent to user %d", wsEvent.UserID)
						default:
							log.Printf("[Hub] ✗ ERROR: Channel full for user %d, disconnecting", c.userID)
							go func(cl *Client) { s.unregister <- cl }(c)
						}
						// Don't break - send to ALL connections for this user (multiple tabs)
					}
				}
				if sentCount == 0 {
					log.Printf("[Hub] WARNING: No clients found for user %d", targetUserID)
				}
			} else if wsEvent, ok := message.(*protocol.WebSocketEvent); ok {
				// Broadcast to all connected clients (UserID == 0)
				fmt.Printf("[Hub] Broadcasting event %s to all %d connected clients\n", wsEvent.Type, len(s.clients))
				for c := range s.clients {
					select {
					case c.send <- message:
					default:
						go func(cl *Client) { s.unregister <- cl }(c)
					}
				}
			} else {
				// Non-WebSocketEvent broadcast
				fmt.Printf("[Hub] Broadcasting non-WebSocketEvent message to all %d connected clients\n", len(s.clients))
				for c := range s.clients {
					select {
					case c.send <- message:
					default:
						go func(cl *Client) { s.unregister <- cl }(c)
					}
				}
			}
			s.mu.RUnlock()
		}
	}
}

// readPump reads messages from the WebSocket connection
func (c *Client) readPump() {
	defer func() {
		c.server.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(protocol.ReadDeadline)
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		var msg protocol.GatewayResponse
		err := c.conn.ReadJSON(&msg)
		if err != nil {
			break
		}

		// TODO: Process message based on type if needed
		// Currently, clients handle WebSocket messages on the client-side
	}
}

// writePump writes messages to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				// Channel closed
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteJSON(message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// Contact handlers
func (s *Server) handleGetContacts(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	contacts, err := s.contactSvc.GetContacts(ctx, claims.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"contacts": contacts})
}

func (s *Server) handleGetPendingRequests(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	requests, err := s.contactSvc.GetPendingRequests(ctx, claims.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"requests": requests})
}

func (s *Server) handleContactRequest(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Parse JSON request body
	var req struct {
		Action    string `json:"action"`
		ContactID int64  `json:"contact_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Action == "" {
		http.Error(w, "Missing action", http.StatusBadRequest)
		return
	}

	if req.ContactID == 0 {
		http.Error(w, "Missing or invalid contact_id", http.StatusBadRequest)
		return
	}

	contactReq := &protocol.ContactRequest{
		Action:    req.Action,
		UserID:    claims.UserID,
		ContactID: req.ContactID,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resp, err := s.contactSvc.ProcessContactRequest(ctx, contactReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Contact service already handles WebSocket broadcasts via broadcastHandler
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Chat handlers
func (s *Server) handleGetChats(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	chats, err := s.chatSvc.GetUserChats(ctx, claims.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(chats)
}

func (s *Server) handleCreateChat(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Parse JSON request body
	var req struct {
		User2ID   int64  `json:"user2_id"`
		Algorithm string `json:"algorithm"`
		Mode      string `json:"mode"`
		Padding   string `json:"padding"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.User2ID == 0 || req.Algorithm == "" || req.Mode == "" || req.Padding == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	chatReq := &protocol.ChatCreateRequest{
		User1ID:   claims.UserID,
		User2ID:   req.User2ID,
		Algorithm: req.Algorithm,
		Mode:      req.Mode,
		Padding:   req.Padding,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resp, err := s.chatSvc.CreateChat(ctx, chatReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleCloseChat(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	chatID := parseInt(vars["chatID"])

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resp, err := s.chatSvc.CloseChat(ctx, chatID, claims.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Broadcast chat closed event to the other participant
	if resp.Success {
		// Get the chat to find the other user
		chatData, err := s.chatSvc.GetStore().GetChat(chatID)
		if err != nil {
			fmt.Printf("[Chat] ERROR: Failed to get chat after closing: %v\n", err)
		} else if chatData != nil {
			// Determine which user is the other participant
			var otherUserID int64
			if chatData.User1ID == claims.UserID {
				otherUserID = chatData.User2ID
			} else {
				otherUserID = chatData.User1ID
			}

			// Send targeted chat_closed event to the other participant
			wsEvent := &protocol.WebSocketEvent{
				Type:      "chat_closed",
				UserID:    otherUserID, // Targeted to the other user
				Timestamp: time.Now().Unix(),
				Data: map[string]interface{}{
					"chat_id": chatID,
					"user_id": claims.UserID, // The user who closed the chat
				},
			}
			fmt.Printf("[Chat] Broadcasting chat_closed for chat %d to user %d (initiator: %d)\n", chatID, otherUserID, claims.UserID)
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			select {
			case s.broadcast <- wsEvent:
				fmt.Printf("[Chat] ✓ chat_closed event queued for user %d\n", otherUserID)
			case <-ctxTimeout.Done():
				fmt.Printf("[Chat] ERROR: chat_closed broadcast timeout for user %d\n", otherUserID)
			default:
				fmt.Printf("[Chat] WARNING: chat_closed broadcast channel full for user %d\n", otherUserID)
			}
			cancel()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleJoinChat(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	chatID := parseInt(vars["chatID"])

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resp, err := s.chatSvc.JoinChat(ctx, chatID, claims.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleLeaveChat(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	chatID := parseInt(vars["chatID"])

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	resp, err := s.chatSvc.LeaveChat(ctx, chatID, claims.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Message handlers
func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	_, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	chatID := parseInt(vars["chatID"])

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	messages, err := s.messageSvc.GetChatMessages(ctx, chatID, 50, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Convert []byte ciphertext/iv to hex strings to match client expectations
	outMessages := make([]map[string]interface{}, 0, len(messages))
	for _, m := range messages {
		out := map[string]interface{}{
			"id":         m.ID,
			"chat_id":    m.ChatID,
			"sender_id":  m.SenderID,
			"ciphertext": hex.EncodeToString(m.Ciphertext),
			"iv":         hex.EncodeToString(m.IV),
			"timestamp":  m.Timestamp,
		}
		if m.FileName != "" {
			out["file_name"] = m.FileName
		}
		if m.MimeType != "" {
			out["mime_type"] = m.MimeType
		}
		outMessages = append(outMessages, out)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"messages": outMessages})
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var req struct {
		ChatID     int64  `json:"chat_id"`
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
		FileName   string `json:"file_name"`
		MimeType   string `json:"mime_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Accept hex-encoded ciphertext/iv from clients (E2E runner sends hex strings)
	var ctBytes, ivBytes []byte
	if req.Ciphertext != "" {
		b, err := hex.DecodeString(req.Ciphertext)
		if err != nil {
			http.Error(w, "invalid ciphertext hex", http.StatusBadRequest)
			return
		}
		ctBytes = b
	}
	if req.IV != "" {
		b, err := hex.DecodeString(req.IV)
		if err != nil {
			http.Error(w, "invalid iv hex", http.StatusBadRequest)
			return
		}
		ivBytes = b
	}

	msg := &protocol.EncryptedMessage{
		ChatID:     req.ChatID,
		SenderID:   claims.UserID,
		Ciphertext: ctBytes,
		IV:         ivBytes,
		Timestamp:  time.Now().Unix(),
		FileName:   req.FileName,
		MimeType:   req.MimeType,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	if err := s.messageSvc.ProcessMessage(ctx, msg); err != nil {
		log.Printf("Error processing message: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func parseInt(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// Broadcast sends a message to all connected clients
func (s *Server) Broadcast(msg interface{}) {
	// Try to send broadcast message with small timeout
	// This ensures messages are delivered even under load
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	select {
	case s.broadcast <- msg:
		if wsEvent, ok := msg.(*protocol.WebSocketEvent); ok {
			log.Printf("[Gateway] Broadcast queued: type=%s, userID=%d", wsEvent.Type, wsEvent.UserID)
		}
	case <-ctx.Done():
		if wsEvent, ok := msg.(*protocol.WebSocketEvent); ok {
			log.Printf("[Gateway] ERROR: Broadcast timeout for type=%s, userID=%d - channel may be full", wsEvent.Type, wsEvent.UserID)
		} else {
			log.Printf("[Gateway] ERROR: Broadcast timeout - channel may be full")
		}
	}
}

// DH Key Exchange handlers
func (s *Server) handleDHInit(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	chatIDStr := vars["chatID"]
	chatID := parseInt(chatIDStr)

	if chatID == 0 {
		log.Printf("DEBUG: chatIDStr='%s', parsed chatID=%d", chatIDStr, chatID)
		http.Error(w, "Invalid chat ID", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Initiate DH key exchange for this chat
	dhParams, err := s.chatSvc.InitiateDHExchange(ctx, chatID, claims.UserID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dhParams)
}

func (s *Server) handleDHExchange(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Missing authorization token", http.StatusUnauthorized)
		return
	}

	token := extractToken(authHeader)
	if token == "" {
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	claims, err := s.authSvc.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	chatID := parseInt(vars["chatID"])

	if chatID == 0 {
		http.Error(w, "Invalid chat ID", http.StatusBadRequest)
		return
	}

	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" {
		http.Error(w, "Missing public_key", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Complete DH key exchange and derive session key
	if err := s.chatSvc.CompleteDHExchange(ctx, chatID, claims.UserID, req.PublicKey); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}
