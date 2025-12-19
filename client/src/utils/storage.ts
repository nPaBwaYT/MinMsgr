// LocalStorage utilities for consistent data access

const STORAGE_KEYS = {
  TOKEN: 'token',
  USER_ID: 'userId',
  USERNAME: 'username',
  DH_PRIVATE_KEY: 'dh_private_key',
  ENCRYPTED_PRIVATE_KEY: 'encrypted_private_key',
} as const;

/**
 * Get user token from storage
 */
export function getStoredToken(): string | null {
  return localStorage.getItem(STORAGE_KEYS.TOKEN);
}

/**
 * Set user token in storage
 */
export function setStoredToken(token: string): void {
  localStorage.setItem(STORAGE_KEYS.TOKEN, token);
}

/**
 * Get user ID from storage
 */
export function getStoredUserId(): number {
  const id = localStorage.getItem(STORAGE_KEYS.USER_ID);
  return id ? parseInt(id, 10) : 0;
}

/**
 * Set user ID in storage
 */
export function setStoredUserId(userId: number): void {
  localStorage.setItem(STORAGE_KEYS.USER_ID, userId.toString());
}

/**
 * Get username from storage
 */
export function getStoredUsername(): string | null {
  return localStorage.getItem(STORAGE_KEYS.USERNAME);
}

/**
 * Set username in storage
 */
export function setStoredUsername(username: string): void {
  localStorage.setItem(STORAGE_KEYS.USERNAME, username);
}

/**
 * Get DH private key from storage
 */
export function getStoredDHPrivateKey(): string | null {
  return localStorage.getItem(STORAGE_KEYS.DH_PRIVATE_KEY);
}

/**
 * Set DH private key in storage
 */
export function setStoredDHPrivateKey(key: string): void {
  localStorage.setItem(STORAGE_KEYS.DH_PRIVATE_KEY, key);
}

/**
 * Get encrypted private key from storage
 */
export function getStoredEncryptedPrivateKey(): string | null {
  return localStorage.getItem(STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY);
}

/**
 * Set encrypted private key in storage
 */
export function setStoredEncryptedPrivateKey(key: string): void {
  localStorage.setItem(STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY, key);
}

/**
 * Clear all authentication and DH keys
 */
export function clearAuthKeys(): void {
  localStorage.removeItem(STORAGE_KEYS.TOKEN);
  localStorage.removeItem(STORAGE_KEYS.USER_ID);
  localStorage.removeItem(STORAGE_KEYS.USERNAME);
  localStorage.removeItem(STORAGE_KEYS.DH_PRIVATE_KEY);
  localStorage.removeItem(STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY);
}

/**
 * Clear only DH keys
 */
export function clearDHKeys(): void {
  localStorage.removeItem(STORAGE_KEYS.DH_PRIVATE_KEY);
  localStorage.removeItem(STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY);
}

/**
 * Check if user is logged in (has token and user ID)
 */
export function isLoggedIn(): boolean {
  return !!getStoredToken() && getStoredUserId() > 0;
}
