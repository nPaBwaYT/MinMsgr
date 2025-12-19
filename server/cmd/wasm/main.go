//go:build js && wasm
// +build js,wasm

package main

import (
	"fmt"
	"syscall/js"

	"MinMsgr/server/internal/pkg/encryption"
)

func main() {
	fmt.Println("WASM Crypto Module Initialized")

	// Register all WASM functions
	encryption.RegisterWasmFunctions()

	// Export a ready flag to signal that WASM is ready
	js.Global().Set("WasmReady", js.ValueOf(true))
	fmt.Println("WASM module ready: WasmReady = true")

	// Keep the program running indefinitely
	// This is required for Go WASM programs
	<-make(chan struct{})
}
