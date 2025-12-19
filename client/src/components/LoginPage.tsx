import React, { useState } from 'react';
import apiService from '../api';
import { encryptPrivateKeyWithPassword, decryptPrivateKeyWithPassword } from '../crypto';

interface LoginProps {
  onLoginSuccess: (userId: number, username: string, token: string) => void;
}

export const LoginPage: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isRegister, setIsRegister] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (isRegister) {
        // Fetch global DH parameters from server
        const dhParams = await apiService.getGlobalDHParams();
        console.log('[Register] Fetched global DH params, p length:', dhParams.p.length, 'g:', dhParams.g);
        
        // Create DH instance and generate persistent key pair
        const dh = new (await import('../crypto')).DiffieHellman(dhParams.p, dhParams.g);
        const publicKeyHex = dh.generatePrivateKey();
        const privateKeyHex = dh.getPrivateKeyHex();
        console.log('[Register] Generated private key (hex):');
        console.log('  Length:', privateKeyHex.length, 'chars');
        console.log('  First 40 chars:', privateKeyHex.substring(0, 40));
        console.log('  Last 40 chars:', privateKeyHex.substring(privateKeyHex.length - 40));
        console.log('[Register] Generated public key (hex):');
        console.log('  Length:', publicKeyHex.length, 'chars');
        console.log('  First 40 chars:', publicKeyHex.substring(0, 40));
        
        const encPrivHex = await encryptPrivateKeyWithPassword(privateKeyHex, password);
        console.log('[Register] Encrypted private key with password:');
        console.log('  Encrypted hex length:', encPrivHex.length, 'chars');
        console.log('  First 40 chars:', encPrivHex.substring(0, 40));
        console.log('  Last 40 chars:', encPrivHex.substring(encPrivHex.length - 40));
        console.log('  Format: salt(32) || iv(24) || ciphertext(rest)');

        // Verify encryption/decryption round-trip before sending to server
        console.log('[Register] Verifying encryption/decryption round-trip...');
        let decryptedKeyHex: string;
        try {
          decryptedKeyHex = await decryptPrivateKeyWithPassword(encPrivHex, password);
        } catch (decErr) {
          console.error('[Register] ✗ Decryption failed:', decErr);
          setError('Encryption/decryption failed. Cannot verify encryption. ' + (decErr instanceof Error ? decErr.message : String(decErr)));
          setLoading(false);
          return;
        }
        
        console.log('[Register] Decrypted private key:');
        console.log('  Decrypted hex length:', decryptedKeyHex.length, 'chars');
        console.log('  First 40 chars:', decryptedKeyHex.substring(0, 40));
        console.log('  Last 40 chars:', decryptedKeyHex.substring(decryptedKeyHex.length - 40));
        
        if (decryptedKeyHex === privateKeyHex) {
          console.log('[Register] ✓ Encryption/decryption verification PASSED - keys match');
        } else {
          console.error('[Register] ✗ Encryption/decryption verification FAILED - keys do NOT match');
          console.error('[Register] Original key length:', privateKeyHex.length);
          console.error('[Register] Decrypted key length:', decryptedKeyHex.length);
          console.error('[Register] Original key first 40:', privateKeyHex.substring(0, 40));
          console.error('[Register] Decrypted key first 40:', decryptedKeyHex.substring(0, 40));
          console.error('[Register] Original key last 40:', privateKeyHex.substring(privateKeyHex.length - 40));
          console.error('[Register] Decrypted key last 40:', decryptedKeyHex.substring(decryptedKeyHex.length - 40));
          setError('Encryption verification failed. Keys do not match after decryption.');
          setLoading(false);
          return;
        }

        let registerResp;
        try {
          registerResp = await apiService.register(username, password, publicKeyHex, encPrivHex);
          console.log('[Register] Sent registration to server with public_key and encrypted_private_key');
          console.log('[Register] Server response:', registerResp);
        } catch (regErr: any) {
          const errMsg = regErr.response?.data?.error || (regErr instanceof Error ? regErr.message : String(regErr));
          console.error('[Register] ✗ Registration failed:', errMsg);
          
          if (errMsg.includes('username already exists')) {
            setError('Username already exists. Please choose a different username or login instead.');
          } else {
            setError('Registration failed: ' + errMsg);
          }
          setLoading(false);
          return;
        }
        
        // Persist private key locally so the client can compute shared secrets immediately
        try {
          localStorage.setItem('dh_private_key', privateKeyHex);
          localStorage.setItem('encrypted_private_key', encPrivHex);
          console.log('[Register] ✓ Stored dh_private_key and encrypted_private_key in localStorage');
          console.log('[Register] Private key successfully persisted for later chat use');
        } catch (e) {
          console.warn('[Register] Failed to store DH private key locally:', e);
        }

        // Now login to get token and verify public key
        try {
          console.log('[Register] Attempting automatic login after registration...');
          const loginResp = await apiService.login(username, password);
          const token = loginResp.token;
          
          // Store token temporarily to verify public key
          localStorage.setItem('token', token);
          
          // Fetch stored public key from server to verify it matches
          const pubKeyResp = await apiService.getMyPublicKey();
          const storedPublicKeyHex = pubKeyResp.public_key;
          
          if (storedPublicKeyHex === publicKeyHex) {
            console.log('[Register] ✓ PUBLIC KEY VALIDATION PASSED: Stored key matches local key');
          } else {
            console.error('[Register] ✗ PUBLIC KEY MISMATCH!');
            console.error('[Register] Local public key length:', publicKeyHex.length);
            console.error('[Register] Stored public key length:', storedPublicKeyHex.length);
            console.error('[Register] Local first 40:', publicKeyHex.substring(0, 40));
            console.error('[Register] Stored first 40:', storedPublicKeyHex.substring(0, 40));
            setError('Public key mismatch detected. Registration may have failed.')
            return;
          }
          
          // Success - call login callback
          onLoginSuccess(loginResp.user_id, loginResp.username || username, token);
          setError('');
          setIsRegister(false);
        } catch (loginErr: any) {
          console.error('[Register] Auto-login after registration failed:', loginErr);
          setError('Registration successful but auto-login failed. Please login manually.');
          setIsRegister(false);
        }
      } else {
        // Clear old DH keys from previous login to prevent conflicts
        console.log('[Login] Clearing old DH keys from localStorage...');
        localStorage.removeItem('dh_private_key');
        localStorage.removeItem('encrypted_private_key');
        console.log('[Login] ✓ Old DH keys cleared');
        
        const response = await apiService.login(username, password);
        localStorage.setItem('token', response.token);
        localStorage.setItem('userId', response.user_id.toString());
        localStorage.setItem('username', response.username || username);
        console.log('[Login] Authentication successful for user:', response.username);

        // If server returned encrypted private key, decrypt and store locally
        if (response.encrypted_private_key) {
          console.log('[Login] Server returned encrypted_private_key, attempting decryption...');
          console.log('[Login] Received encrypted_private_key:');
          console.log('  Encrypted hex length:', response.encrypted_private_key.length, 'chars');
          console.log('  First 40 chars:', response.encrypted_private_key.substring(0, 40));
          console.log('  Last 40 chars:', response.encrypted_private_key.substring(response.encrypted_private_key.length - 40));
          
          try {
            const privHex = await decryptPrivateKeyWithPassword(response.encrypted_private_key, password);
            console.log('[Login] ✓ Successfully decrypted private key:');
            console.log('  Decrypted hex length:', privHex.length, 'chars');
            console.log('  First 40 chars:', privHex.substring(0, 40));
            console.log('  Last 40 chars:', privHex.substring(privHex.length - 40));
            localStorage.setItem('dh_private_key', privHex);
            localStorage.setItem('encrypted_private_key', response.encrypted_private_key);
            console.log('[Login] ✓ Stored decrypted dh_private_key and encrypted_private_key in localStorage');
          } catch (e) {
            console.error('[Login] ✗ Failed to decrypt stored private key:', e);
            setError('Failed to decrypt your stored encryption key. Password may be incorrect.');
          }
        } else {
          console.warn('[Login] No encrypted_private_key returned from server');
        }

        onLoginSuccess(response.user_id, response.username, response.token);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center p-4">
      <div className="bg-white rounded-lg shadow-xl p-8 w-full max-w-md">
        <h1 className="text-3xl font-bold text-center mb-8 text-gray-800">
          MinMessenger
        </h1>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Enter username"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Enter password"
              required
            />
          </div>

          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded-lg transition disabled:opacity-50"
          >
            {loading ? 'Processing...' : isRegister ? 'Register' : 'Login'}
          </button>
        </form>

        <button
          onClick={() => setIsRegister(!isRegister)}
          className="w-full mt-4 text-center text-blue-500 hover:text-blue-700 font-medium text-sm"
        >
          {isRegister
            ? 'Already have an account? Login'
            : "Don't have an account? Register"}
        </button>
      </div>
    </div>
  );
};
