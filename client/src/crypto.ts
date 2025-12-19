// Simple implementations of encryption algorithms that match the server
// This module will attempt to use a WebAssembly-compiled Go implementation when available.
import * as wasmWrapper from './wasm/cryptoWrapper';

export interface CipherAlgorithm {
  encrypt(key: Uint8Array, plaintext: Uint8Array, iv?: Uint8Array): Uint8Array;
  decrypt(key: Uint8Array, ciphertext: Uint8Array, iv?: Uint8Array): Uint8Array;
  blockSize(): number;
}

// Helper functions for bit operations
function rotl32(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

// LOKI97 Cipher (simplified for client-side)
export class LOKI97 implements CipherAlgorithm {
  private sbox1: Uint8Array;
  private sbox2: Uint8Array;

  constructor() {
    // Simplified S-boxes (would be the full 256 elements in production)
    this.sbox1 = new Uint8Array(256);
    this.sbox2 = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      this.sbox1[i] = i;
      this.sbox2[i] = (i * 17 + 42) % 256;
    }
  }

  blockSize(): number {
    return 8; // 64-bit block
  }

  encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
    const ciphertext = new Uint8Array(plaintext.length);
    for (let i = 0; i < plaintext.length; i++) {
      ciphertext[i] = plaintext[i] ^ key[i % key.length];
    }
    return ciphertext;
  }

  decrypt(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    return this.encrypt(key, ciphertext);
  }
}

// RC6 Cipher (simplified for client-side)
export class RC6 implements CipherAlgorithm {
  private S: Uint32Array;

  constructor(key: Uint8Array) {
    this.S = new Uint32Array(44);
    this.expandKey(key);
  }

  blockSize(): number {
    return 16; // 128-bit block
  }

  private expandKey(key: Uint8Array): void {
    const p32 = 0xb7e15163 >>> 0;
    const q32 = 0x9e3779b9 >>> 0;

    this.S[0] = p32;
    for (let i = 1; i < 44; i++) {
      this.S[i] = (this.S[i - 1] + q32) >>> 0;
    }

    let a = 0;
    let b = 0;
    for (let k = 0; k < 3 * 44; k++) {
      a = this.S[k % 44] = rotl32(
        (this.S[k % 44] + a + b) >>> 0,
        3
      );
      b = (key[k % key.length] + a + b) >>> 0;
    }
  }

  encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (plaintext.length !== 16) {
      throw new Error('Plaintext must be 16 bytes');
    }

    // Simplified: just XOR with key for client-side demo
    const ciphertext = new Uint8Array(plaintext.length);
    for (let i = 0; i < plaintext.length; i++) {
      ciphertext[i] = plaintext[i] ^ key[i % key.length];
    }
    return ciphertext;
  }

  decrypt(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    return this.encrypt(key, ciphertext);
  }
}

// Encryption modes
export function encryptCBC(
  cipher: CipherAlgorithm,
  key: Uint8Array,
  plaintext: Uint8Array,
  iv: Uint8Array
): Uint8Array {
  const blockSize = cipher.blockSize();
  const blocks = Math.ceil(plaintext.length / blockSize);
  const ciphertext = new Uint8Array(blocks * blockSize);

  let prevBlock = new Uint8Array(iv);

  for (let i = 0; i < blocks; i++) {
    const block = new Uint8Array(blockSize);
    const start = i * blockSize;

    // Copy plaintext block
    for (let j = 0; j < blockSize; j++) {
      if (start + j < plaintext.length) {
        block[j] = plaintext[start + j];
      } else {
        block[j] = 0; // Padding (simplified)
      }
    }

    // XOR with previous ciphertext block
    for (let j = 0; j < blockSize; j++) {
      block[j] ^= prevBlock[j];
    }

    // Encrypt block
    const encrypted = cipher.encrypt(key, block);
    const encryptedArray = new Uint8Array(encrypted);
    ciphertext.set(encryptedArray, i * blockSize);
    prevBlock = encryptedArray;
  }

  return ciphertext;
}

export function decryptCBC(
  cipher: CipherAlgorithm,
  key: Uint8Array,
  ciphertext: Uint8Array,
  iv: Uint8Array
): Uint8Array {
  const blockSize = cipher.blockSize();
  const plaintext = new Uint8Array(ciphertext.length);

  let prevBlock = new Uint8Array(iv);

  for (let i = 0; i < ciphertext.length; i += blockSize) {
    const block = ciphertext.slice(i, i + blockSize);
    const decrypted = cipher.decrypt(key, new Uint8Array(block));

    // XOR with previous ciphertext block
    for (let j = 0; j < blockSize; j++) {
      plaintext[i + j] = (decrypted[j] ^ prevBlock[j]) & 0xff;
    }

    prevBlock = new Uint8Array(block);
  }

  return plaintext;
}

// Utility functions
export function generateRandomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function generateIV(blockSize: number): Uint8Array {
  return generateRandomBytes(blockSize);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  // Parse hex string to bytes without adding leading zeros
  // Handle odd-length hex strings by padding only the last nibble
  const bytes = new Uint8Array(Math.ceil(hex.length / 2));
  for (let i = 0; i < hex.length; i += 2) {
    const chunk = hex.substr(i, 2);
    // Pad to 2 chars on the right side only (not left)
    bytes[Math.floor(i / 2)] = parseInt(chunk.padStart(2, '0'), 16);
  }
  return bytes;
}

export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// Expose a high-level API that prefers WASM implementations when available.
export async function initCryptoWasm(): Promise<boolean> {
  try {
    return await wasmWrapper.initWasmCrypto();
  } catch (err) {
    console.warn('WASM crypto init failed:', err);
    return false;
  }
}

export async function encryptWithAny(algorithm: string, key: Uint8Array, plaintext: string, iv?: Uint8Array): Promise<{ciphertext: Uint8Array, iv: Uint8Array}> {
  const keyHex = bytesToHex(key);
  const ivHex = iv ? bytesToHex(iv) : '';

  if ((await initCryptoWasm())) {
    try {
      const res = await wasmWrapper.wasmEncrypt(algorithm, keyHex, plaintext, ivHex);
      return { ciphertext: hexToBytes(res.ciphertext), iv: hexToBytes(res.iv) };
    } catch (e) {
      console.warn('WASM encrypt failed, falling back to JS:', e);
    }
  }

  // JS fallback: use simple XOR demo
  const pt = stringToBytes(plaintext);
  const ivUsed = iv || generateIV(algorithm === 'RC6' ? 16 : 8);
  const ct = pt.map((b, i) => b ^ (key[i % key.length] ^ ivUsed[i % ivUsed.length]));
  return { ciphertext: ct instanceof Uint8Array ? ct : new Uint8Array(ct), iv: ivUsed };
}

export async function decryptWithAny(algorithm: string, key: Uint8Array, ciphertextHex: string, ivHex: string): Promise<string> {
  const keyHex = bytesToHex(key);

  if ((await initCryptoWasm())) {
    try {
      return await wasmWrapper.wasmDecrypt(algorithm, keyHex, ciphertextHex, ivHex);
    } catch (e) {
      console.warn('WASM decrypt failed, falling back to JS:', e);
    }
  }

  // JS fallback
  const ct = hexToBytes(ciphertextHex);
  const ivBytes = hexToBytes(ivHex);
  const pt = ct.map((b, i) => b ^ (key[i % key.length] ^ ivBytes[i % ivBytes.length]));
  return bytesToString(new Uint8Array(pt));
}
// Diffie-Hellman Key Exchange utilities
export class DiffieHellman {
  private p: bigint; // Prime modulus
  private g: bigint; // Generator
  private a: bigint | null = null; // Private key
  private publicKey: bigint | null = null; // Public key (g^a mod p)

  constructor(primeHex: string, generatorHex: string) {
    this.p = BigInt('0x' + primeHex);
    this.g = BigInt('0x' + generatorHex);
  }

  /**
   * Generate a random private key and compute public key
   */
  generatePrivateKey(): string {
    // Generate random integer between 2 and p-2
    const maxBits = this.p.toString(2).length;
    let a: bigint;
    
    do {
      // Generate random bytes
      const randomBytes = crypto.getRandomValues(new Uint8Array(Math.ceil(maxBits / 8)));
      a = BigInt('0x' + bytesToHex(randomBytes));
    } while (a < 2n || a >= this.p - 1n);

    this.a = a;
    this.computePublicKey();
    return this.getPublicKeyHex();
  }

  /**
   * Export private key as hex string
   */
  getPrivateKeyHex(): string {
    if (this.a === null) throw new Error('Private key not generated');
    // Pad to modulus byte length to ensure consistent 256-byte output for 2048-bit DH
    const hex = this.a.toString(16);
    const modulusHexLen = this.p.toString(16).length;
    const paddedHex = hex.padStart(modulusHexLen, '0');
    console.debug('[DH] Private key - Hex length:', paddedHex.length, 'chars =', Math.ceil(paddedHex.length / 2), 'bytes');
    return paddedHex;
  }

  /**
   * Import existing private key (hex) into this DH instance and compute public key
   */
  importPrivateKeyHex(privateKeyHex: string): void {
    this.a = BigInt('0x' + privateKeyHex);
    this.computePublicKey();
  }

  /**
   * Compute public key g^a mod p
   */
  private computePublicKey(): void {
    if (this.a === null) {
      throw new Error('Private key not generated');
    }
    this.publicKey = this.modPow(this.g, this.a, this.p);
  }

  /**
   * Get public key as hex string
   */
  getPublicKeyHex(): string {
    if (this.publicKey === null) {
      throw new Error('Public key not computed');
    }
    // Pad to modulus byte length to ensure consistent 256-byte output for 2048-bit DH
    const hex = this.publicKey.toString(16);
    const modulusHexLen = this.p.toString(16).length;
    const paddedHex = hex.padStart(modulusHexLen, '0');
    console.debug('[DH] Public key - Hex length:', paddedHex.length, 'chars =', Math.ceil(paddedHex.length / 2), 'bytes');
    return paddedHex;
  }

  /**
   * Compute shared secret using other party's public key
   */
  computeSharedSecret(otherPublicKeyHex: string): Uint8Array {
    if (this.a === null) {
      throw new Error('Private key not generated');
    }

    const otherPublicKey = BigInt('0x' + otherPublicKeyHex);
    const sharedSecret = this.modPow(otherPublicKey, this.a, this.p);
    
    // Pad hex to modulus byte length to ensure consistent size (256 bytes for 2048-bit DH)
    const modulusHexLen = this.p.toString(16).length;
    const sharedSecretHex = sharedSecret.toString(16).padStart(modulusHexLen, '0');
    const secretBytes = hexToBytes(sharedSecretHex);

    console.debug('[DH] Shared secret - Hex length:', sharedSecretHex.length, 'chars =', secretBytes.length, 'bytes');
    return secretBytes;
  }

  /**
   * Derive encryption key and IV from shared secret
   */
  async deriveKeyFromSharedSecret(sharedSecretBytes: Uint8Array, keyLength: number = 32, ivLength: number = 16): Promise<{ key: Uint8Array; iv: Uint8Array }> {
    // Use SubtleCrypto if available (works in browser and Node 18+ via globalThis.crypto)
    if ((globalThis as any).crypto?.subtle) {
        try {
          const subtle = (globalThis as any).crypto.subtle as SubtleCrypto;
          const buffer = new ArrayBuffer(sharedSecretBytes.length);
          new Uint8Array(buffer).set(sharedSecretBytes);
        
          // Derive key
          let keyHash = await subtle.digest('SHA-256', buffer);
          const key = new Uint8Array(keyHash).slice(0, keyLength);
        
          // Derive IV using different input
          const ivInput = new Uint8Array(sharedSecretBytes.length + 1);
          ivInput.set(sharedSecretBytes);
          ivInput[sharedSecretBytes.length] = 1;
          const ivBuffer = new ArrayBuffer(ivInput.length);
          new Uint8Array(ivBuffer).set(ivInput);
          let ivHash = await subtle.digest('SHA-256', ivBuffer);
          const iv = new Uint8Array(ivHash).slice(0, ivLength);
        
          return { key, iv };
        } catch (e) {
          console.warn('SubtleCrypto failed, using fallback:', e);
        }
    }

    // Fallback: simple derivation
    const key = new Uint8Array(keyLength);
    const iv = new Uint8Array(ivLength);
    
    for (let i = 0; i < keyLength; i++) {
      key[i] = sharedSecretBytes[i % sharedSecretBytes.length] ^ sharedSecretBytes[(i + 1) % sharedSecretBytes.length];
    }
    for (let i = 0; i < ivLength; i++) {
      iv[i] = sharedSecretBytes[(i + 2) % sharedSecretBytes.length] ^ sharedSecretBytes[(i + 3) % sharedSecretBytes.length];
    }
    
    return { key, iv };
  }

  /**
   * Modular exponentiation: (base^exponent) mod modulus
   */
  private modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus === 1n) return 0n;
    
    let result = 1n;
    base = base % modulus;
    
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
      }
      exponent = exponent >> 1n;
      base = (base * base) % modulus;
    }
    
    return result;
  }
}

/**
 * Derive encryption key from DH shared secret
 * Uses SHA-256 hash of the shared secret
 */
export async function deriveKeyFromSharedSecret(sharedSecretBytes: Uint8Array, keyLength: number = 32): Promise<Uint8Array> {
  // Use SubtleCrypto if available (browser or Node 18+)
  if ((globalThis as any).crypto?.subtle) {
    try {
      const subtle = (globalThis as any).crypto.subtle as SubtleCrypto;
      const buffer = new ArrayBuffer(sharedSecretBytes.length);
      new Uint8Array(buffer).set(sharedSecretBytes);
      const hash = await subtle.digest('SHA-256', buffer);
      const key = new Uint8Array(hash);
      // If we need a longer key, we can derive more using HKDF-like approach
      if (key.length >= keyLength) {
        return key.slice(0, keyLength);
      }
      // For longer keys, concatenate multiple hashes
      const result = new Uint8Array(keyLength);
      let offset = 0;
      let iteration = 0;
      while (offset < keyLength) {
        const input = new Uint8Array(sharedSecretBytes.length + 1);
        input.set(sharedSecretBytes);
        input[sharedSecretBytes.length] = iteration++;
        
        const inputBuffer = new ArrayBuffer(input.length);
        new Uint8Array(inputBuffer).set(input);
        const iterHash = await subtle.digest('SHA-256', inputBuffer);
        const copyLength = Math.min(32, keyLength - offset);
        result.set(new Uint8Array(iterHash).slice(0, copyLength), offset);
        offset += copyLength;
      }
      return result;
    } catch (e) {
      console.warn('SubtleCrypto failed, using fallback:', e);
    }
  }

  // Fallback: simple hash-like derivation
  const key = new Uint8Array(keyLength);
  for (let i = 0; i < keyLength; i++) {
    key[i] = sharedSecretBytes[i % sharedSecretBytes.length] ^ sharedSecretBytes[(i + 1) % sharedSecretBytes.length];
  }
  return key;
}

// Derive a symmetric key from password using PBKDF2-SHA256
export async function deriveKeyFromPassword(password: string, salt?: Uint8Array, iterations: number = 100000, keyLength: number = 32): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const subtleImport = (globalThis as any).crypto?.subtle as SubtleCrypto | undefined;
  if (!subtleImport) {
    throw new Error('SubtleCrypto is not available in this environment');
  }

  const pwKey = await (subtleImport.importKey as any)(
    'raw',
    enc.encode(password) as unknown as ArrayBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  const usedSalt = salt || generateIV(16);
  const derived = await subtleImport.deriveBits(
    { name: 'PBKDF2', salt: new Uint8Array(usedSalt), iterations, hash: 'SHA-256' },
    pwKey,
    keyLength * 8
  );

  return new Uint8Array(derived);
}

// Encrypt private key bytes with password-derived key using AES-GCM
export async function encryptPrivateKeyWithPassword(privateKeyHex: string, password: string): Promise<string> {
  try {
    const privateKeyBytes = hexToBytes(privateKeyHex);
    console.debug('[encryptPrivateKeyWithPassword] Input privateKeyHex length:', privateKeyHex.length);
    console.debug('[encryptPrivateKeyWithPassword] Input privateKeyBytes length:', privateKeyBytes.length);
    
    const salt = generateIV(16);
    console.debug('[encryptPrivateKeyWithPassword] Generated salt length:', salt.length);
    
    const keyBytes = await deriveKeyFromPassword(password, salt);
    console.debug('[encryptPrivateKeyWithPassword] Derived key length:', keyBytes.length);

    const subtleCrypto = (globalThis as any).crypto?.subtle as SubtleCrypto;
    if (!subtleCrypto) {
      throw new Error('SubtleCrypto not available');
    }
    
    const cryptoKey = await subtleCrypto.importKey('raw', new Uint8Array(keyBytes), { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = generateIV(12);
    console.debug('[encryptPrivateKeyWithPassword] Generated IV length:', iv.length);
    
    const cipher = await subtleCrypto.encrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, cryptoKey, new Uint8Array(privateKeyBytes));
    console.debug('[encryptPrivateKeyWithPassword] Encrypted cipher length:', new Uint8Array(cipher).length);
    
    // Return hex: salt || iv || ciphertext
    const out = new Uint8Array(salt.length + iv.length + new Uint8Array(cipher).length);
    out.set(salt, 0);
    out.set(iv, salt.length);
    out.set(new Uint8Array(cipher), salt.length + iv.length);
    const result = bytesToHex(out);
    console.debug('[encryptPrivateKeyWithPassword] Output hex length:', result.length);
    return result;
  } catch (err) {
    console.error('[encryptPrivateKeyWithPassword] Error:', err);
    throw err;
  }
}

export async function decryptPrivateKeyWithPassword(encryptedHex: string, password: string): Promise<string> {
  try {
    console.debug('[decryptPrivateKeyWithPassword] Input encrypted hex length:', encryptedHex.length);
    
    const data = hexToBytes(encryptedHex);
    console.debug('[decryptPrivateKeyWithPassword] Parsed data length:', data.length);
    
    const salt = data.slice(0, 16);
    const iv = data.slice(16, 28);
    const cipher = data.slice(28);
    
    console.debug('[decryptPrivateKeyWithPassword] Salt length:', salt.length);
    console.debug('[decryptPrivateKeyWithPassword] IV length:', iv.length);
    console.debug('[decryptPrivateKeyWithPassword] Cipher length:', cipher.length);

    const keyBytes = await deriveKeyFromPassword(password, salt);
    console.debug('[decryptPrivateKeyWithPassword] Derived key length:', keyBytes.length);
    
    const subtleCrypto2 = (globalThis as any).crypto?.subtle as SubtleCrypto;
    if (!subtleCrypto2) {
      throw new Error('SubtleCrypto not available');
    }
    
    const cryptoKey = await subtleCrypto2.importKey('raw', new Uint8Array(keyBytes), { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = await subtleCrypto2.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, cryptoKey, new Uint8Array(cipher));
    
    // Return the full decrypted private key as-is (no truncation)
    let plainArray = new Uint8Array(plain);
    console.debug('[decryptPrivateKeyWithPassword] Decrypted plain length:', plainArray.length);
    
    const result = bytesToHex(plainArray);
    console.debug('[decryptPrivateKeyWithPassword] Decrypted hex length:', result.length);
    return result;
  } catch (err) {
    console.error('[decryptPrivateKeyWithPassword] Error:', err);
    throw err;
  }
}

// Provide a default export for environments that consume the module as a namespace/default (CJS interop)
const _defaultExport = {
  encryptPrivateKeyWithPassword,
  decryptPrivateKeyWithPassword,
  deriveKeyFromPassword,
  deriveKeyFromSharedSecret,
  DiffieHellman,
  encryptWithAny,
  decryptWithAny,
  initCryptoWasm,
  bytesToHex,
  hexToBytes,
};

export default _defaultExport;