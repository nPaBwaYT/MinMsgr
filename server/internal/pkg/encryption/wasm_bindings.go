//go:build js && wasm
// +build js,wasm

package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"syscall/js"
)

// helper: pad PKCS7
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	padtext := make([]byte, len(data)+padding)
	copy(padtext, data)
	for i := len(data); i < len(padtext); i++ {
		padtext[i] = byte(padding)
	}
	return padtext
}

func pkcs7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	pad := int(data[len(data)-1])
	if pad <= 0 || pad > len(data) {
		return data
	}
	return data[:len(data)-pad]
}

func bytesToHex(b []byte) string          { return hex.EncodeToString(b) }
func hexToBytes(s string) ([]byte, error) { return hex.DecodeString(s) }

func registerWasm() {
	// WasmCrypto.Encrypt(algorithm, keyHex, plaintextHex, ivHex) -> json string {ciphertext, iv}
	encrypt := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 4 {
			return js.ValueOf(map[string]string{"error": "insufficient args"})
		}
		alg := args[0].String()
		keyHex := args[1].String()
		ptHex := args[2].String()
		ivHex := args[3].String()

		key, err := hexToBytes(keyHex)
		if err != nil {
			return js.ValueOf(map[string]string{"error": "invalid key hex"})
		}
		pt, err := hexToBytes(ptHex)
		if err != nil {
			return js.ValueOf(map[string]string{"error": "invalid plaintext hex"})
		}

		var iv []byte
		if ivHex != "" {
			iv, _ = hexToBytes(ivHex)
		}

		var cipherBlocks [][]byte
		var blockSize int

		switch alg {
		case "LOKI97":
			c, err := NewLOKI97(key)
			if err != nil {
				return js.ValueOf(map[string]string{"error": err.Error()})
			}
			blockSize = c.BlockSize()
			data := pkcs7Pad(pt, blockSize)
			for i := 0; i < len(data); i += blockSize {
				blk := data[i : i+blockSize]
				enc, err := c.Encrypt(key, blk)
				if err != nil {
					return js.ValueOf(map[string]string{"error": err.Error()})
				}
				cipherBlocks = append(cipherBlocks, enc)
			}
		case "RC6":
			c, err := NewRC6(key)
			if err != nil {
				return js.ValueOf(map[string]string{"error": err.Error()})
			}
			blockSize = c.BlockSize()
			data := pkcs7Pad(pt, blockSize)
			for i := 0; i < len(data); i += blockSize {
				blk := data[i : i+blockSize]
				enc, err := c.Encrypt(key, blk)
				if err != nil {
					return js.ValueOf(map[string]string{"error": err.Error()})
				}
				cipherBlocks = append(cipherBlocks, enc)
			}
		default:
			return js.ValueOf(map[string]string{"error": "unknown algorithm"})
		}

		// join blocks
		var out []byte
		for _, b := range cipherBlocks {
			out = append(out, b...)
		}

		// ensure iv
		if len(iv) == 0 {
			iv = make([]byte, blockSize)
			rand.Read(iv)
		}

		// Create JavaScript object explicitly
		result := js.Global().Get("Object").New()
		result.Set("ciphertext", bytesToHex(out))
		result.Set("iv", bytesToHex(iv))
		fmt.Println("[GO] Encrypt returning object with ciphertext and iv")
		return result
	})

	decrypt := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 4 {
			return js.ValueOf(map[string]string{"error": "insufficient args"})
		}
		alg := args[0].String()
		keyHex := args[1].String()
		ctHex := args[2].String()
		ivHex := args[3].String()

		key, err := hexToBytes(keyHex)
		if err != nil {
			return js.ValueOf(map[string]string{"error": "invalid key hex"})
		}
		ct, err := hexToBytes(ctHex)
		if err != nil {
			return js.ValueOf(map[string]string{"error": "invalid ciphertext hex"})
		}
		_ = ivHex // IV is available but not used in ECB-like decryption

		var blockSize int
		var out []byte

		switch alg {
		case "LOKI97":
			c, err := NewLOKI97(key)
			if err != nil {
				return js.ValueOf(map[string]string{"error": err.Error()})
			}
			blockSize = c.BlockSize()
			for i := 0; i < len(ct); i += blockSize {
				blk := ct[i : i+blockSize]
				dec, err := c.Decrypt(key, blk)
				if err != nil {
					return js.ValueOf(map[string]string{"error": err.Error()})
				}
				out = append(out, dec...)
			}
		case "RC6":
			c, err := NewRC6(key)
			if err != nil {
				return js.ValueOf(map[string]string{"error": err.Error()})
			}
			blockSize = c.BlockSize()
			for i := 0; i < len(ct); i += blockSize {
				blk := ct[i : i+blockSize]
				dec, err := c.Decrypt(key, blk)
				if err != nil {
					return js.ValueOf(map[string]string{"error": err.Error()})
				}
				out = append(out, dec...)
			}
		default:
			return js.ValueOf(map[string]string{"error": "unknown algorithm"})
		}

		// unpad
		out = pkcs7Unpad(out)

		// Create JavaScript object explicitly
		result := js.Global().Get("Object").New()
		result.Set("plaintext", bytesToHex(out))
		fmt.Println("[GO] Decrypt returning object with plaintext")
		return result
	})

	// Create wrappers that accept mode and padding (even though we ignore them for now)
	encryptWithMode := js.FuncOf(func(this js.Value, args []js.Value) (result any) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("[GO] EncryptWithMode panic:", r)
				errObj := js.Global().Get("Object").New()
				errObj.Set("error", fmt.Sprintf("panic: %v", r))
				result = errObj
			}
		}()

		if len(args) < 6 {
			fmt.Println("[GO] EncryptWithMode: insufficient args")
			result = js.Global().Get("Object").New()
			(result).(js.Value).Set("error", "insufficient args")
			return
		}

		fmt.Println("[GO] EncryptWithMode: starting...")
		// For now, just call the encrypt logic directly
		// args: algorithm, keyHex, plaintextHex, ivHex, mode, padding
		// We'll ignore mode and padding since basic Encrypt/Decrypt uses ECB

		// Safely get string values - check each arg for null/undefined
		if args[0].IsNull() || args[0].IsUndefined() {
			fmt.Println("[GO] EncryptWithMode: algorithm is null or undefined")
			obj := js.Global().Get("Object").New()
			obj.Set("error", "algorithm is null or undefined")
			result = obj
			return
		}
		alg := args[0].String()

		if args[1].IsNull() || args[1].IsUndefined() {
			fmt.Println("[GO] EncryptWithMode: keyHex is null or undefined")
			obj := js.Global().Get("Object").New()
			obj.Set("error", "keyHex is null or undefined")
			result = obj
			return
		}
		keyHex := args[1].String()

		if args[2].IsNull() || args[2].IsUndefined() {
			fmt.Println("[GO] EncryptWithMode: plaintext is null or undefined")
			obj := js.Global().Get("Object").New()
			obj.Set("error", "plaintext is null or undefined")
			result = obj
			return
		}

		// Safely convert to string - use Type() to check
		ptHex := ""
		if args[2].Type().String() == "string" {
			ptHex = args[2].String()
		} else {
			fmt.Println("[GO] EncryptWithMode: plaintext is not a string, type is:", args[2].Type().String())
			obj := js.Global().Get("Object").New()
			obj.Set("error", "plaintext must be a string, got: "+args[2].Type().String())
			result = obj
			return
		}

		if args[3].IsNull() || args[3].IsUndefined() {
			fmt.Println("[GO] EncryptWithMode: ivHex is null or undefined")
			obj := js.Global().Get("Object").New()
			obj.Set("error", "ivHex is null or undefined")
			result = obj
			return
		}
		ivHex := args[3].String()

		fmt.Printf("[GO] EncryptWithMode: algorithm=%s, keyHex len=%d, ptHex len=%d\n", alg, len(keyHex), len(ptHex))

		key, err := hexToBytes(keyHex)
		if err != nil {
			fmt.Println("[GO] EncryptWithMode: invalid key hex:", err)
			obj := js.Global().Get("Object").New()
			obj.Set("error", "invalid key hex")
			result = obj
			return
		}
		pt, err := hexToBytes(ptHex)
		if err != nil {
			fmt.Println("[GO] EncryptWithMode: invalid plaintext hex:", err)
			obj := js.Global().Get("Object").New()
			obj.Set("error", "invalid plaintext hex")
			result = obj
			return
		}

		var iv []byte
		if ivHex != "" {
			iv, _ = hexToBytes(ivHex)
		}

		var cipherBlocks [][]byte
		var blockSize int

		switch alg {
		case "LOKI97":
			c, err := NewLOKI97(key)
			if err != nil {
				fmt.Println("[GO] EncryptWithMode: NewLOKI97 error:", err)
				obj := js.Global().Get("Object").New()
				obj.Set("error", err.Error())
				result = obj
				return
			}
			blockSize = c.BlockSize()
			data := pkcs7Pad(pt, blockSize)
			for i := 0; i < len(data); i += blockSize {
				blk := data[i : i+blockSize]
				enc, err := c.Encrypt(key, blk)
				if err != nil {
					fmt.Println("[GO] EncryptWithMode: Encrypt error:", err)
					obj := js.Global().Get("Object").New()
					obj.Set("error", err.Error())
					result = obj
					return
				}
				cipherBlocks = append(cipherBlocks, enc)
			}
		case "RC6":
			c, err := NewRC6(key)
			if err != nil {
				fmt.Println("[GO] EncryptWithMode: NewRC6 error:", err)
				obj := js.Global().Get("Object").New()
				obj.Set("error", err.Error())
				result = obj
				return
			}
			blockSize = c.BlockSize()
			data := pkcs7Pad(pt, blockSize)
			for i := 0; i < len(data); i += blockSize {
				blk := data[i : i+blockSize]
				enc, err := c.Encrypt(key, blk)
				if err != nil {
					fmt.Println("[GO] EncryptWithMode: Encrypt error:", err)
					obj := js.Global().Get("Object").New()
					obj.Set("error", err.Error())
					result = obj
					return
				}
				cipherBlocks = append(cipherBlocks, enc)
			}
		default:
			fmt.Println("[GO] EncryptWithMode: unknown algorithm:", alg)
			obj := js.Global().Get("Object").New()
			obj.Set("error", "unknown algorithm")
			result = obj
			return
		}

		var out []byte
		for _, b := range cipherBlocks {
			out = append(out, b...)
		}

		if len(iv) == 0 {
			iv = make([]byte, blockSize)
			rand.Read(iv)
		}

		// Create JavaScript object explicitly
		fmt.Println("[GO] EncryptWithMode: creating result object...")
		obj := js.Global().Get("Object").New()
		obj.Set("ciphertext", bytesToHex(out))
		obj.Set("iv", bytesToHex(iv))
		fmt.Println("[GO] EncryptWithMode: returning object successfully")
		result = obj
		return
	})

	decryptWithMode := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 6 {
			return js.ValueOf(map[string]string{"error": "insufficient args"})
		}
		// For now, just call the decrypt logic directly
		// args: algorithm, keyHex, ciphertextHex, ivHex, mode, padding
		// We'll ignore mode and padding
		alg := args[0].String()
		keyHex := args[1].String()
		ctHex := args[2].String()
		ivHex := args[3].String() // Add this line
		_ = ivHex                 // IV is available but not used in ECB-like decryption

		key, err := hexToBytes(keyHex)
		if err != nil {
			return js.ValueOf(map[string]string{"error": "invalid key hex"})
		}
		ct, err := hexToBytes(ctHex)
		if err != nil {
			return js.ValueOf(map[string]string{"error": "invalid ciphertext hex"})
		}

		var blockSize int
		var out []byte

		switch alg {
		case "LOKI97":
			c, err := NewLOKI97(key)
			if err != nil {
				return js.ValueOf(map[string]string{"error": err.Error()})
			}
			blockSize = c.BlockSize()
			for i := 0; i < len(ct); i += blockSize {
				blk := ct[i : i+blockSize]
				dec, err := c.Decrypt(key, blk)
				if err != nil {
					return js.ValueOf(map[string]string{"error": err.Error()})
				}
				out = append(out, dec...)
			}
		case "RC6":
			c, err := NewRC6(key)
			if err != nil {
				return js.ValueOf(map[string]string{"error": err.Error()})
			}
			blockSize = c.BlockSize()
			for i := 0; i < len(ct); i += blockSize {
				blk := ct[i : i+blockSize]
				dec, err := c.Decrypt(key, blk)
				if err != nil {
					return js.ValueOf(map[string]string{"error": err.Error()})
				}
				out = append(out, dec...)
			}
		default:
			return js.ValueOf(map[string]string{"error": "unknown algorithm"})
		}

		out = pkcs7Unpad(out)

		// Create JavaScript object explicitly
		result := js.Global().Get("Object").New()
		result.Set("plaintext", bytesToHex(out))
		fmt.Println("[GO] DecryptWithMode returning object with plaintext")
		return result
	})

	wasmObj := js.Global().Get("WasmCrypto")
	// Check if WasmCrypto exists by attempting to get it
	createIfNeeded := wasmObj.Type() == js.TypeUndefined
	if createIfNeeded {
		wasmObj = js.Global().Get("Object").New()
		js.Global().Set("WasmCrypto", wasmObj)
	}
	wasmObj.Set("Encrypt", encrypt)
	wasmObj.Set("Decrypt", decrypt)
	wasmObj.Set("EncryptWithMode", encryptWithMode)
	wasmObj.Set("DecryptWithMode", decryptWithMode)
}

// RegisterWasmFunctions registers all WASM functions with JavaScript
func RegisterWasmFunctions() {
	registerWasm()
}
