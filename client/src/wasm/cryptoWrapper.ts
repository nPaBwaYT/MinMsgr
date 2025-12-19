import { initGoWasm } from './loader';
import { bytesToHex, hexToBytes, stringToBytes, bytesToString } from '../crypto';

let wasmAvailable = false;

export async function initWasmCrypto(): Promise<boolean> {
  // wasm should be served from /crypto.wasm (client/public/crypto.wasm)
  console.log('[WASM] Attempting to initialize crypto.wasm...');
  wasmAvailable = await initGoWasm('/crypto.wasm');

  // Wait a bit for Go to fully initialize
  if (wasmAvailable) {
    console.log('[WASM] ⏳ Waiting for WASM to fully initialize...');
    await new Promise(resolve => setTimeout(resolve, 100));
  }


  // Expect the Go code to attach a global `WasmCrypto` object with methods
  if (wasmAvailable && typeof (window as any).WasmCrypto === 'object') {
    console.log('[WASM] ✅ WASM Crypto initialization SUCCESS');
    console.log('[WASM] WasmCrypto object available with methods:', {
      hasEncrypt: typeof (window as any).WasmCrypto.Encrypt === 'function',
      hasDecrypt: typeof (window as any).WasmCrypto.Decrypt === 'function',
      hasEncryptWithMode: typeof (window as any).WasmCrypto.EncryptWithMode === 'function',
      hasDecryptWithMode: typeof (window as any).WasmCrypto.DecryptWithMode === 'function'
    });
    return true;
  }

  wasmAvailable = false;
 
  return false;
}

function hasWasm(): boolean {
  const isAvailable = wasmAvailable && typeof (window as any).WasmCrypto === 'object';
  if (!isAvailable) {
    console.debug('[WASM] hasWasm() = false (wasmAvailable=%s, WasmCrypto=%s)', 
      wasmAvailable, 
      typeof (window as any).WasmCrypto
    );
  }
  return isAvailable;
}

/**
 * List of supported encryption modes
 */
export const SUPPORTED_MODES = [
  'ECB',           // Electronic Codebook
  'CBC',           // Cipher Block Chaining
  'PCBC',          // Propagating Cipher Block Chaining
  'CFB',           // Cipher Feedback
  'OFB',           // Output Feedback
  'CTR',           // Counter Mode
  'RANDOM_DELTA'   // Custom stream mode
] as const;

export type EncryptionMode = typeof SUPPORTED_MODES[number];

/**
 * List of supported padding schemes
 */
export const SUPPORTED_PADDINGS = [
  'ZEROS',         // Simple zero-byte padding
  'PKCS7',         // PKCS#7 padding (recommended)
  'ANSI_X923',     // ANSI X.923 padding
  'ISO_10126'      // ISO 10126 padding (randomized)
] as const;

export type PaddingScheme = typeof SUPPORTED_PADDINGS[number];

/**
 * Check if a mode is supported
 */
export function isSupportedMode(mode: string): mode is EncryptionMode {
  return SUPPORTED_MODES.includes(mode as EncryptionMode);
}

/**
 * Check if a padding scheme is supported
 */
export function isSupportedPadding(padding: string): padding is PaddingScheme {
  return SUPPORTED_PADDINGS.includes(padding as PaddingScheme);
}

/**
 * Get default recommendations for mode and padding
 */
export function getDefaultModeAndPadding(): { mode: EncryptionMode; padding: PaddingScheme } {
  return {
    mode: 'CBC',        // Secure and widely supported
    padding: 'PKCS7'    // Standard and unambiguous
  };
}

/**
 * Validate encryption configuration
 */
export function validateEncryptionConfig(mode?: string, padding?: string): { mode: EncryptionMode; padding: PaddingScheme } {
  const defaults = getDefaultModeAndPadding();

  const validMode = mode && isSupportedMode(mode) ? mode : defaults.mode;
  const validPadding = padding && isSupportedPadding(padding) ? padding : defaults.padding;

  return { mode: validMode, padding: validPadding };
}

/**
 * Check if mode requires IV
 */
export function modeRequiresIV(mode: EncryptionMode): boolean {
  return mode !== 'ECB';
}

/**
 * Get block size for algorithm
 * RC6 = 16 bytes, LOKI97 = 8 bytes
 */
export function getBlockSize(algorithm: string): number {
  if (algorithm.toUpperCase() === 'RC6') {
    return 16; // 128-bit blocks
  } else if (algorithm.toUpperCase() === 'LOKI97') {
    return 8; // 64-bit blocks
  }
  throw new Error(`Unknown algorithm: ${algorithm}`);
}

/**
 * Get required key size for algorithm
 * LOKI97 = 16 bytes, RC6 = 16 bytes
 */
export function getKeySize(algorithm: string): number {
  if (algorithm.toUpperCase() === 'RC6') {
    return 16; // 128-bit key
  } else if (algorithm.toUpperCase() === 'LOKI97') {
    return 16; // 128-bit key
  }
  throw new Error(`Unknown algorithm: ${algorithm}`);
}

/**
 * Normalize a key to the required size for an algorithm
 * Uses SHA-256 hash and truncation/padding
 */
export async function normalizeKey(algorithm: string, keyHex: string): Promise<string> {
  const requiredSize = getKeySize(algorithm);
  const keyBytes = hexToBytes(keyHex);
  
  // If key is already the right size, return as-is
  if (keyBytes.length === requiredSize) {
    console.debug(`[Crypto] Key already correct size: ${keyBytes.length} bytes`);
    return keyHex;
  }
  
  console.debug(`[Crypto] Normalizing key from ${keyBytes.length} bytes to ${requiredSize} bytes using SHA-256`);
  
  // Hash the key using SHA-256 and use first N bytes
  // Copy to ensure we have regular ArrayBuffer, not SharedArrayBuffer
  const keyBytesCopy = new Uint8Array(keyBytes);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBytesCopy);
  const hashBytes = new Uint8Array(hashBuffer);
  
  // Truncate or use as-is based on required size
  const normalizedBytes = new Uint8Array(requiredSize);
  for (let i = 0; i < requiredSize; i++) {
    normalizedBytes[i] = hashBytes[i % hashBytes.length];
  }
  
  const normalizedHex = bytesToHex(normalizedBytes);
  console.debug(`[Crypto] Key normalized: ${normalizedBytes.length} bytes`);
  return normalizedHex;
}

/**
 * Generate random hex string
 */
export function generateRandomHex(bytes: number): string {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return bytesToHex(arr);
}

// Example high-level wrapper functions. These call into global WasmCrypto if present.
export async function wasmEncrypt(algorithm: string, keyHex: string, plaintextHex: string, ivHex?: string): Promise<{ciphertext: string, iv: string}> {
  const wc = (window as any).WasmCrypto;
  // Assume the wasm exposes a function `Encrypt(algorithm, keyHex, plaintextHex, ivHex) -> {ciphertextHex, ivHex}`
  return wc.Encrypt(algorithm, keyHex, plaintextHex, ivHex || '');
  

}

export async function wasmDecrypt(algorithm: string, keyHex: string, ciphertextHex: string, ivHex: string): Promise<string> {
  
  const wc = (window as any).WasmCrypto;
  return wc.Decrypt(algorithm, keyHex, ciphertextHex, ivHex);

}

/**
 * Encrypt with specified mode and padding
 * Delegates to WASM if available
 */
export async function wasmEncryptWithMode(
  algorithm: string,
  keyHex: string,
  plaintextHex: string,
  ivHex: string,
): Promise<{ ciphertext: string; iv: string }> {

  const wc = (window as any).WasmCrypto;
  
  

  // Fallback to basic Encrypt
  if (typeof wc.Encrypt === 'function') {
    const result = wc.Encrypt(algorithm, keyHex, plaintextHex, ivHex || '');
    console.log('[wasmEncrypt] Got result:', result);
    if (!result || typeof result !== 'object') {
      throw new Error('Encrypt returned invalid result: ' + typeof result);
    }
    return result;
  }

  throw new Error('WasmCrypto.Encrypt not found');
}

/**
 * Decrypt with specified mode and padding
 * Delegates to WASM if available
 */
export async function wasmDecryptWithMode(
  algorithm: string,
  keyHex: string,
  ciphertextHex: string,
  ivHex: string,
  mode: string = 'CBC',
  padding: string = 'PKCS7'
): Promise<string> {
  if (!hasWasm()) {
    throw new Error('WASM crypto not available');
  }

  const wc = (window as any).WasmCrypto;

  // Try to use DecryptWithMode if available (new API)
  if (typeof wc.DecryptWithMode === 'function') {
    const result = wc.DecryptWithMode(algorithm, keyHex, ciphertextHex, ivHex, mode, padding);
    
    if (!result || typeof result !== 'object') {
      throw new Error('DecryptWithMode returned invalid result: ' + typeof result);
    }
    if (!result.plaintext) {
      throw new Error('DecryptWithMode result has no plaintext property');
    }
    return result.plaintext;
  }

  // Fallback to basic Decrypt
  if (typeof wc.Decrypt === 'function') {
    const result = wc.Decrypt(algorithm, keyHex, ciphertextHex, ivHex);
    console.log('[wasmDecrypt] Got result:', result);
    if (!result || typeof result !== 'object') {
      throw new Error('Decrypt returned invalid result: ' + typeof result);
    }
    if (!result.plaintext) {
      throw new Error('Decrypt result has no plaintext property');
    }
    return result.plaintext;
  }

  throw new Error('WasmCrypto.Decrypt not found');
}

/**
 * High-level API: Encrypt message with mode and padding
 * Returns hex-encoded ciphertext and IV
 */
export async function encryptMessage(
  algorithm: string,
  keyHex: string,
  message: string,
  mode: string = 'CBC',
  padding: string = 'PKCS7',
  ivHex?: string
): Promise<{ ciphertext: string; iv: string; mode: string; padding: string }> {
  // Validate configuration
  const { mode: validMode, padding: validPadding } = validateEncryptionConfig(mode, padding);

  // Normalize key to match algorithm requirements
  const normalizedKeyHex = await normalizeKey(algorithm, keyHex);

  // Generate IV if not provided
  const useIvHex = ivHex || generateRandomHex(getBlockSize(algorithm));

  
  if (hasWasm()) {
    console.debug('[Crypto] WASM available - using native encryption');
    const plaintextHex = bytesToHex(stringToBytes(message));
    const result = await wasmEncryptWithMode(
      algorithm,
      normalizedKeyHex,
      plaintextHex,
      useIvHex
    );
    console.debug('[Crypto] ✅ WASM encryption succeeded');
    return {
      ...result,
      mode: validMode,
      padding: validPadding
    };
  } else {
    console.warn('[Crypto] ⚠️ WASM NOT available - will use XOR fallback');
  }
  

  const plaintextBytes = stringToBytes(message);
  const keyBytes = hexToBytes(normalizedKeyHex);
  const ivBytes = hexToBytes(useIvHex);
  
  const ciphertext = plaintextBytes.map((b, i) => 
    b ^ (keyBytes[i % keyBytes.length] ^ ivBytes[i % ivBytes.length])
  );

  return {
    ciphertext: bytesToHex(ciphertext),
    iv: useIvHex,
    mode: validMode,
    padding: validPadding
  };
}

/**
 * High-level API: Decrypt message with mode and padding
 * Takes hex-encoded ciphertext and IV
 */
export async function decryptMessage(
  algorithm: string,
  keyHex: string,
  ciphertextHex: string,
  ivHex: string,
  mode: string = 'CBC',
  padding: string = 'PKCS7'
): Promise<string> {
  // Validate configuration
  const { mode: validMode, padding: validPadding } = validateEncryptionConfig(mode, padding);

  // Normalize key to match algorithm requirements
  const normalizedKeyHex = await normalizeKey(algorithm, keyHex);


  if (hasWasm()) {
    console.debug('[Crypto] WASM available - using native decryption');
    const plaintextHex = await wasmDecryptWithMode(
      algorithm,
      normalizedKeyHex,
      ciphertextHex,
      ivHex,
      validMode,
      validPadding
    );
    console.debug('[Crypto] ✅ WASM decryption succeeded');
    return bytesToString(hexToBytes(plaintextHex));

  }
  

  // Fallback: simple XOR (not secure, for demo only)

  const ciphertextBytes = hexToBytes(ciphertextHex);
  const keyBytes = hexToBytes(normalizedKeyHex);
  const ivBytes = hexToBytes(ivHex);
  
  const plaintext = ciphertextBytes.map((b, i) => 
    b ^ (keyBytes[i % keyBytes.length] ^ ivBytes[i % ivBytes.length])
  );

  return bytesToString(plaintext);
}

/**
 * Export available modes and paddings for UI configuration
 */
export const ENCRYPTION_CONFIG = {
  modes: SUPPORTED_MODES,
  paddings: SUPPORTED_PADDINGS,
  defaults: getDefaultModeAndPadding(),
  modeDescriptions: {
    ECB: 'Electronic Codebook - Simple, no IV needed (not recommended for large data)',
    CBC: 'Cipher Block Chaining - Recommended, industry standard',
    PCBC: 'Propagating CBC - Enhanced error detection capabilities',
    CFB: 'Cipher Feedback - Stream mode for variable-length data',
    OFB: 'Output Feedback - Parallelizable stream mode',
    CTR: 'Counter Mode - High performance, fully parallelizable',
    RANDOM_DELTA: 'Random Delta Stream - Custom stream cipher with random state evolution'
  } as Record<EncryptionMode, string>,
  paddingDescriptions: {
    ZEROS: 'Zero-byte padding - Simple but ambiguous',
    PKCS7: 'PKCS#7 padding - Standard, recommended choice',
    ANSI_X923: 'ANSI X.923 padding - ANSI standard, good security',
    ISO_10126: 'ISO 10126 padding - Randomized, highest security'
  } as Record<PaddingScheme, string>
};
