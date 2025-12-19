package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"MinMsgr/server/internal/api/gateway"
	"MinMsgr/server/internal/config"
	"MinMsgr/server/internal/services/auth"
	"MinMsgr/server/internal/services/chat"
	"MinMsgr/server/internal/services/contact"
	"MinMsgr/server/internal/services/message"
	"MinMsgr/server/internal/storage"
)

func main() {
	// Load configuration
	cfg := config.Load()
	fmt.Println("Configuration loaded:")
	fmt.Println(cfg)

	// Connect to database with retries
	dbConfig := storage.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		Database: cfg.Database.Database,
		SSLMode:  cfg.Database.SSLMode,
	}

	var db *storage.DB
	var err error
	maxRetries := 30
	retryDelay := 2 * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {
		db, err = storage.New(dbConfig)
		if err == nil {
			fmt.Printf("✓ Connected to database (attempt %d)\n", attempt)
			break
		}

		if attempt < maxRetries {
			fmt.Printf("✗ Failed to connect to database (attempt %d/%d): %v\n", attempt, maxRetries, err)
			fmt.Printf("  Retrying in %v...\n", retryDelay)
			time.Sleep(retryDelay)
		} else {
			log.Fatalf("Failed to connect to database after %d attempts: %v", maxRetries, err)
		}
	}
	defer db.Close()

	// Initialize database schema
	if err := db.InitSchema(); err != nil {
		log.Fatalf("Failed to initialize database schema: %v", err)
	}
	fmt.Println("Database schema initialized")

	// Create services
	authService := auth.New(cfg.JWT.Secret, db)
	contactService := contact.NewService(db)
	chatService := chat.NewService(db)
	messageService := message.NewService(db)

	// Ensure global DH parameters exist (seed if necessary)
	func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p, g, err := chatService.GetGlobalDHParams(ctx)
		if err != nil {
			log.Printf("Warning: failed to ensure global DH params: %v", err)
		} else {
			if p != nil && g != nil {
				log.Printf("Global DH parameters initialized (p length=%d, g length=%d)", len(p), len(g))
			}
		}
	}()

	// Create gateway server with services
	gatewayServer := gateway.New(
		fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		authService,
		contactService,
		chatService,
		messageService,
	)

	// Start gateway server
	if err := gatewayServer.Start(); err != nil {
		log.Fatalf("Gateway server failed: %v", err)
	}
}
