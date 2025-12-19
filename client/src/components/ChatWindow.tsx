import React, { useState, useEffect, useRef } from 'react';
import apiService, { wsService } from '../api';
import { db, Chat } from '../db';
import { stringToBytes, bytesToString, bytesToHex, hexToBytes, generateIV, DiffieHellman } from '../crypto';
import { encryptMessage as wasmEncryptMessage, decryptMessage as wasmDecryptMessage } from '../wasm/cryptoWrapper';

interface ChatWindowProps {
  userId: number;
  chat: Chat;
  onClose: () => void;
}

export const ChatWindow: React.FC<ChatWindowProps> = ({ userId, chat, onClose }) => {
  const [messages, setMessages] = useState<any[]>([]);
  const [messageText, setMessageText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [encryptProgress, setEncryptProgress] = useState(0);
  const [sessionKey, setSessionKey] = useState<Uint8Array | null>(null);
  const [sessionIV, setSessionIV] = useState<Uint8Array | null>(null);
  const [dhInitialized, setDhInitialized] = useState(false);
  const [dhProgress, setDhProgress] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  console.debug('[ChatWindow] Mounted with chat:', { chat, userId });

  // Initialize DH key exchange when chat opens
  useEffect(() => {
    console.debug('[ChatWindow] useEffect triggered', { chatId: chat?.id, user1Id: chat?.user1Id, user2Id: chat?.user2Id });
    if (!chat || !chat.id || chat.user1Id === undefined || chat.user2Id === undefined) {
      console.warn('[DH] Chat data is incomplete', { chat });
      setError('Chat data is incomplete');
      return;
    }

    // Clear messages, keys, and state when switching to new chat
    console.log('[ChatWindow] Switching to new chat, clearing old state');
    setMessages([]);
    setSessionKey(null);
    setSessionIV(null);
    setDhInitialized(false);
    setMessageText('');
    setSelectedFile(null);
    setError('');

    let unsubscribe: (() => void) | null = null;

    (async () => {
      try {
        unsubscribe = await initializeDHExchange();
      } catch (e) {
        console.error('[ChatWindow] Failed to initialize chat:', e);
      }
    })();

    return () => {
      // Unsubscribe from WebSocket messages
      if (unsubscribe) {
        unsubscribe();
        console.debug('[ChatWindow] Unsubscribed from messages');
      }
      
      // leave chat on unmount
      (async () => {
        try {
          if (chat && chat.id) {
            await apiService.leaveChat(chat.id);
            console.debug('[DH] Left chat on unmount', { chatId: chat.id });
          }
        } catch (e) {
          console.warn('[DH] leaveChat failed during unmount', e);
        }
      })();
    };
  }, [chat?.id]);

  const initializeDHExchange = async (): Promise<() => void> => {
    try {
      if (!chat || !chat.id) {
        throw new Error('Chat ID is not available');
      }

      try {
        console.debug('[DH] Attempting joinChat', { chatId: chat.id });
        await apiService.joinChat(chat.id);
        console.debug('[DH] Successfully joined chat on server');
      } catch (e) {
        console.warn('[DH] joinChat returned error (continuing):', e);
      }

      console.log(`[DH] Starting DH initialization for chat ${chat.id}`);
      setDhProgress('Requesting DH parameters...');

      const dhParams = await apiService.initDHExchange(chat.id);
      console.debug('[DH] Received DH parameters from server', {
        p: dhParams.p ? dhParams.p.substring(0, 20) + '...' : 'null',
        g: dhParams.g,
        other_user_public_key: dhParams.other_user_public_key ? dhParams.other_user_public_key.substring(0, 20) + '...' : 'null'
      });

      const dh = new DiffieHellman(dhParams.p, dhParams.g);
      console.log('[DH] DH Parameters:');
      console.log('[DH]   p (prime, first 40 chars):', dhParams.p.substring(0, 40) + '...');
      console.log('[DH]   g (generator):', dhParams.g);

      setDhProgress('Preparing client key pair...');
      const storedPrivHex = localStorage.getItem('dh_private_key');
      if (!storedPrivHex) {
        throw new Error('No local private key found; please login to restore your encrypted private key from the server or register again');
      }

      dh.importPrivateKeyHex(storedPrivHex);
      const myPublicKeyHex = dh.getPublicKeyHex();
      console.log('[DH] My private key length:', storedPrivHex.length);
      console.log('[DH] My public key A (first 40 chars):', myPublicKeyHex.substring(0, 40) + '...');
      console.log('[DH] My public key A (last 40 chars):', myPublicKeyHex.substring(myPublicKeyHex.length - 40));

      try {
        const serverKeyResp = await apiService.getUserPublicKey(userId);
        const serverPublicKeyHex = serverKeyResp?.public_key;
        if (serverPublicKeyHex && serverPublicKeyHex !== myPublicKeyHex) {
          console.warn('[DH] Public key mismatch!');
          console.warn('[DH]   Server public key:', serverPublicKeyHex?.substring(0, 40) + '...');
          console.warn('[DH]   Computed public key:', myPublicKeyHex.substring(0, 40) + '...');
        } else {
          console.log('[DH] ✓ Public keys match!');
        }
      } catch (e) {
        console.warn('[DH] Could not verify public key:', e);
      }

      console.log('[DH] Getting shared secret...');
      setDhProgress('Computing shared secret...');
      const sharedSecretBytes = dh.computeSharedSecret(dhParams.other_user_public_key);
      const sharedSecretHex = bytesToHex(sharedSecretBytes);
      console.log('[DH] Shared secret computed, first 40 chars:', sharedSecretHex.substring(0, 40) + '...');

      const keyBytes = sharedSecretBytes;
      setSessionKey(keyBytes);
      setSessionIV(new Uint8Array(8)); // Default empty IV for DH

      setDhProgress('');
      setDhInitialized(true);
      console.log('[DH] ✓ DH Exchange complete! Session key initialized.');
      console.log('[ChatWindow] Encryption parameters:', {
        algorithm: chat.algorithm,
        mode: chat.mode,
        padding: chat.padding,
        keyLength: keyBytes.length
      });

      // Load messages after DH is complete - pass keyBytes directly
      await loadMessagesWithKey(keyBytes);

      // Subscribe to WebSocket messages for this chat - pass keyBytes to avoid closure issues
      const unsubscribe = subscribeToMessages(keyBytes);
      
      return unsubscribe;
    } catch (err: any) {
      const errorMsg = err?.message || String(err);
      console.error('[DH] DH Exchange failed:', errorMsg);
      setError(`Encryption setup failed: ${errorMsg}`);
      setDhProgress('');
      return () => {}; // Return empty cleanup function on error
    }
  };

  const subscribeToMessages = (keyBytes: Uint8Array) => {
    // Subscribe to chat_closed events for this chat
    const unsubscribeChatClosed = wsService.subscribe('chat_closed', async (event: any) => {
      console.log('[ChatWindow] *** Received chat_closed event ***');
      console.debug('[ChatWindow] chat_closed data:', event);
      
      const eventChatId = event.data?.chat_id || event.chat_id;
      
      if (eventChatId === chat.id) {
        console.log(`[ChatWindow] Chat ${chat.id} was closed by user ${event.data?.user_id || event.user_id}`);
        console.log('[ChatWindow] Closing chat window and clearing local data');
        
        // Clear local messages for this chat
        try {
          await db.messages.where('chatId').equals(chat.id).delete();
          console.log(`[ChatWindow] Cleared messages for closed chat ${chat.id}`);
        } catch (err) {
          console.warn('[ChatWindow] Failed to clear closed chat messages:', err);
        }
        
        // Set error and close the chat UI
        setError('Chat was closed by the other participant');
        setMessages([]);
        
        // Close the chat window after a short delay
        setTimeout(() => {
          onClose();
        }, 500);
      }
    });

    // Subscribe to message_received events for this chat
    const channelName = `message_${chat.id}`;
    console.log('[ChatWindow] Subscribing to channel:', channelName);
    console.debug('[ChatWindow] Using provided keyBytes:', keyBytes ? `${keyBytes.length} bytes` : 'NOT SET');
    
    const unsubscribeMessages = wsService.subscribe(channelName, async (event: any) => {
      console.log('[ChatWindow] *** Received WebSocket event on', channelName, '***');
      console.debug('[ChatWindow] Raw event:', event);
      
      const m = event.data || event;
      
      if (!m || !m.id) {
        console.warn('[ChatWindow] Invalid message structure');
        return;
      }
      
      const messageId = m.id || m.message_id;
      const senderId = m.sender_id || m.senderId;
      const ciphertext = m.ciphertext;
      const iv = m.iv;
      
      if (!messageId || !senderId || !ciphertext || !iv) {
        console.warn('[ChatWindow] Message missing required fields:', { messageId, senderId, ciphertext, iv });
        return;
      }
      
      const serverTimestamp = m.timestamp ? m.timestamp * 1000 : Date.now();
      const newMessage: any = {
        id: messageId,
        chatId: m.chat_id || m.chatId || chat.id,
        senderId: senderId,
        ciphertext: ciphertext,
        iv: iv,
        timestamp: new Date(serverTimestamp),
        type: 'text',
      };

      try {
        if (!keyBytes || keyBytes.length === 0) {
          console.error('[ChatWindow] Key bytes not available for decryption');
          newMessage.decrypted = '[No session key]';
        } else {
          newMessage.decrypted = await decryptMessageWithKey(ciphertext, iv, keyBytes);
          
          if (newMessage.decrypted && newMessage.decrypted.startsWith('data:')) {
            newMessage.type = 'file';
            if (m.file_name) {
              newMessage.fileName = m.file_name;
            } else {
              const mimeMatch = newMessage.decrypted.match(/data:([^;]+)/);
              const mimeType = mimeMatch ? mimeMatch[1] : 'application/octet-stream';
              const ext = mimeType.split('/')[1] || 'bin';
              newMessage.fileName = `file_${messageId}.${ext}`;
            }
          }
        }
      } catch (err) {
        console.error('[ChatWindow] Failed to decrypt message:', err);
        newMessage.decrypted = '[Decryption failed]';
      }

      // Save to IndexedDB (only if not already there)
      try {
        const existing = await db.messages.get(messageId);
        if (!existing) {
          await db.messages.put(newMessage);
          console.debug('[ChatWindow] Saved message to IndexedDB:', { id: messageId });
        } else {
          console.debug('[ChatWindow] Message already in IndexedDB:', { id: messageId });
        }
      } catch (err) {
        console.warn('[ChatWindow] Failed to save to IndexedDB:', err);
      }

      // Add to UI state if not already there
      setMessages(prev => {
        const isDuplicate = prev.some(msg => msg.id === newMessage.id);
        
        if (isDuplicate) {
          console.debug('[ChatWindow] Message already in state:', { id: newMessage.id });
          return prev;
        }
        
        // Check if this is confirmation for one of our pending messages
        if (senderId === userId) {
          // Look for pending message with same content
          const pendingIndex = prev.findIndex(msg => 
            msg.isPending && msg.senderId === userId && msg.decrypted === newMessage.decrypted
          );
          
          if (pendingIndex !== -1) {
            console.debug('[ChatWindow] Replacing pending message with real ID:', { 
              tempId: prev[pendingIndex].id, 
              realId: newMessage.id 
            });
            // Replace pending message with real message
            const updated = [...prev];
            updated[pendingIndex] = newMessage;
            return updated;
          }
        }
        
        // Otherwise just add as new
        console.debug('[ChatWindow] Adding message to state:', { id: newMessage.id, senderId, isPending: newMessage.isPending });
        return [...prev, newMessage];
      });
    });

    // Return combined unsubscribe function
    return () => {
      console.debug('[ChatWindow] Unsubscribing from both chat_closed and message events');
      unsubscribeChatClosed();
      unsubscribeMessages();
    };
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadMessagesWithKey = async (keyBytes: Uint8Array) => {
    try {
      console.log('[ChatWindow] loadMessagesWithKey: Starting for chat', chat.id);
      
      // Step 1: Get messages from server REST API
      const response = await apiService.getMessages(chat.id);
      const messagesList = response.messages || [];
      console.log('[ChatWindow] Received', messagesList.length, 'messages from REST API');

      // IMPORTANT: Server is source of truth
      // If server returns empty list, clear local database too
      if (messagesList.length === 0) {
        console.log('[ChatWindow] Server returned empty chat, clearing local IndexedDB');
        try {
          const countBefore = await db.messages.where('chatId').equals(chat.id).count();
          await db.messages.where('chatId').equals(chat.id).delete();
          console.log(`[ChatWindow] Cleared ${countBefore} messages from IndexedDB (server is empty)`);
        } catch (err) {
          console.warn('[ChatWindow] Failed to clear IndexedDB:', err);
        }
        setMessages([]);
        return; // Done - empty chat
      }

      // Step 2: Decrypt and format all messages from server
      const decryptedMessages = await Promise.all(
        messagesList.map(async (m: any) => {
          const serverTimestamp = m.timestamp ? m.timestamp * 1000 : Date.now();
          const message: any = {
            id: m.id,
            chatId: m.chat_id,
            senderId: m.sender_id,
            ciphertext: m.ciphertext,
            iv: m.iv,
            timestamp: new Date(serverTimestamp),
            type: 'text',
          };

          try {
            message.decrypted = await decryptMessageWithKey(m.ciphertext, m.iv, keyBytes);
            
            if (message.decrypted && message.decrypted.startsWith('data:')) {
              message.type = 'file';
              if (m.file_name) {
                message.fileName = m.file_name;
              } else {
                const mimeMatch = message.decrypted.match(/data:([^;]+)/);
                const mimeType = mimeMatch ? mimeMatch[1] : 'application/octet-stream';
                const ext = mimeType.split('/')[1] || 'bin';
                message.fileName = `file_${message.id}.${ext}`;
              }
            }
          } catch (err) {
            console.error('[ChatWindow] Failed to decrypt message:', err);
            message.decrypted = '[Decryption failed]';
          }

          return message;
        })
      );

      // Step 3: Save all messages to IndexedDB (will skip duplicates)
      let savedCount = 0;
      for (const msg of decryptedMessages) {
        try {
          const existing = await db.messages.get(msg.id);
          if (!existing) {
            await db.messages.put(msg);
            savedCount++;
          }
        } catch (err) {
          console.warn('[ChatWindow] Error checking/saving message', msg.id, ':', err);
        }
      }
      console.log('[ChatWindow] Saved', savedCount, 'new messages to IndexedDB from server');

      // Step 4: Load all messages from IndexedDB for this chat
      const allMessages = await db.messages.where('chatId').equals(chat.id).toArray();
      console.log('[ChatWindow] Loaded', allMessages.length, 'total messages from IndexedDB');

      // Step 5: Sort and display
      const sorted = allMessages.sort((a, b) => 
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );

      setMessages(sorted);
      console.log('[ChatWindow] Chat', chat.id, 'now has', sorted.length, 'messages (server is source of truth)');
    } catch (err) {
      console.error('[ChatWindow] Failed to load messages:', err);
      setError('Failed to load message history');
    }
  };

  const decryptMessageWithKey = async (ciphertext: string, iv: string, keyBytes: Uint8Array): Promise<string> => {
    console.debug('[ChatWindow.Decrypt] Using parameters:', {
      algorithm: chat.algorithm,
      mode: chat.mode,
      padding: chat.padding,
      ciphertextLength: ciphertext.length,
      ivLength: iv.length
    });

    try {
      console.log('[ChatWindow.Decrypt] Calling wasmDecryptMessage...');
      const plaintext = await wasmDecryptMessage(
        chat.algorithm,
        bytesToHex(keyBytes),
        ciphertext,
        iv,
        chat.mode,
        chat.padding
      );
      
      console.debug('[ChatWindow.Decrypt] ✅ Successfully decrypted:', {
        algorithm: chat.algorithm,
        mode: chat.mode,
        padding: chat.padding,
        plaintextLength: plaintext.length
      });
      
      return plaintext;
    } catch (wasmError) {

      const ciphertextBytes = hexToBytes(ciphertext);
      const ivBytes = hexToBytes(iv);
      const plaintext = ciphertextBytes.map((b, i) => 
        b ^ (keyBytes[i % keyBytes.length] ^ ivBytes[i % ivBytes.length])
      );
      
      
      return bytesToString(plaintext);
    }
  };

  const encryptMessage = async (plaintext: string): Promise<{ ciphertext: string; iv: string }> => {
    if (!sessionKey || !sessionIV) throw new Error('Session key not initialized');

    setEncryptProgress(33);

    console.debug('[ChatWindow.Encrypt] Using parameters:', {
      algorithm: chat.algorithm,
      mode: chat.mode,
      padding: chat.padding,
      plaintextLength: plaintext.length
    });

    try {
      // Use cryptoWrapper with the selected mode and padding from chat
      console.log('[ChatWindow.Encrypt] Calling wasmEncryptMessage...');
      const result = await wasmEncryptMessage(
        chat.algorithm,
        bytesToHex(sessionKey),
        plaintext,
        chat.mode,
        chat.padding
      );

      console.debug('[ChatWindow.Encrypt] ✅ Successfully encrypted using mode:', {
        algorithm: chat.algorithm,
        mode: chat.mode,
        padding: chat.padding,
        ciphertextLength: result.ciphertext.length
      });

      setEncryptProgress(66);
      
      return {
        ciphertext: result.ciphertext,
        iv: result.iv
      };
    } catch (wasmError) {
            
      // Fallback to simple XOR for backward compatibility
      const plaintextBytes = stringToBytes(plaintext);
      const ivBytes = generateIV(16);
      const ciphertextBytes = plaintextBytes.map((b, i) => 
        b ^ (sessionKey[i % sessionKey.length] ^ ivBytes[i % ivBytes.length])
      );
    
      
      return {
        ciphertext: bytesToHex(new Uint8Array(ciphertextBytes)),
        iv: bytesToHex(ivBytes)
      };
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!messageText.trim() && !selectedFile) return;

    if (!sessionKey) {
      setError('Encryption key not initialized yet');
      return;
    }

    setLoading(true);
    setError('');

    try {
      let contentToSend = messageText;
      let fileName: string | undefined;

      if (selectedFile) {
        const reader = new FileReader();
        const fileData = await new Promise<string>((resolve, reject) => {
          reader.onload = () => resolve(reader.result as string);
          reader.onerror = reject;
          reader.readAsDataURL(selectedFile);
        });

        contentToSend = fileData;
        fileName = selectedFile.name;
      }

      const { ciphertext, iv } = await encryptMessage(contentToSend);
      setEncryptProgress(90);

      let mimeType: string | undefined;
      if (selectedFile) {
        mimeType = selectedFile.type || 'application/octet-stream';
      }

      // Create a temporary message with a temp ID for immediate UI feedback
      const tempId = -(Date.now()); // Negative ID for temporary messages
      const tempMessage: any = {
        id: tempId,
        chatId: chat.id,
        senderId: userId,
        ciphertext,
        iv,
        timestamp: new Date(),
        type: selectedFile ? 'file' : 'text',
        decrypted: contentToSend,
        fileName: fileName,
        isPending: true, // Flag to show it's pending confirmation
      };

      // Show message immediately in UI
      setMessages(prev => {
        console.debug('[ChatWindow] Added pending message to state:', { 
          id: tempId, 
          contentPreview: contentToSend?.substring(0, 40) 
        });
        return [...prev, tempMessage];
      });

      // Send message to server
      await apiService.sendMessage(chat.id, ciphertext, iv, fileName, mimeType);
      console.debug('[ChatWindow] Message sent to server, waiting for WebSocket with real ID...');

      // Clear form
      setMessageText('');
      setSelectedFile(null);
      setEncryptProgress(100);
      setTimeout(() => setEncryptProgress(0), 500);
    } catch (err) {
      setError('Failed to send message');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSelectedFile(e.target.files?.[0] || null);
  };

  const otherUserId = chat.user1Id === userId ? chat.user2Id : chat.user1Id;

  const clearChatMessages = async () => {
    if (chat && chat.id) {
      try {
        const countBefore = await db.messages.where('chatId').equals(chat.id).count();
        await db.messages.where('chatId').equals(chat.id).delete();
        console.log(`[ChatWindow] Cleared ${countBefore} messages for chat ${chat.id} from IndexedDB`);
        setMessages([]);
        console.log(`[ChatWindow] Cleared messages from React state`);
      } catch (e) {
        console.error(`[ChatWindow] Failed to clear messages for chat ${chat.id}:`, e);
      }
    }
  };

  const handleClose = async () => {
    try {
      if (chat && chat.id) {
        await apiService.leaveChat(chat.id);
      }
    } catch (e) {
      console.warn('leaveChat failed on close', e);
    }
    onClose();
  };

  const handleCloseSecretChat = async () => {
    try {
      if (chat && chat.id) {
        console.log(`[ChatWindow] Clearing messages for chat ${chat.id} before closing...`);
        await clearChatMessages();
        console.log(`[ChatWindow] Closing chat ${chat.id} on server...`);
        await apiService.closeChat(chat.id);
        console.log(`[ChatWindow] Chat ${chat.id} closed on server`);
      }
    } catch (e) {
      console.error('closeChat failed', e);
      setError('Failed to close secret chat');
      return;
    }

    try {
      if (chat && chat.id) {
        console.log(`[ChatWindow] Leaving chat ${chat.id}...`);
        await apiService.leaveChat(chat.id);
        console.log(`[ChatWindow] Left chat ${chat.id}`);
      }
    } catch (e) {
      console.warn('leaveChat after close failed', e);
    }

    console.log(`[ChatWindow] Closing chat UI`);
    onClose();
  };

  return (
    <div className="h-full flex flex-col bg-white rounded-lg shadow">
      <div className="flex items-center justify-between p-4 border-b border-gray-200">
        <div>
          <h2 className="text-xl font-bold text-gray-800">Chat with User {otherUserId}</h2>
          <p className="text-sm text-gray-500">
            {chat.algorithm} • {chat.mode} • {chat.padding}
          </p>
          {dhProgress && <p className="text-xs text-blue-600 mt-1">🔐 {dhProgress}</p>}
          {dhInitialized && <p className="text-xs text-green-600 mt-1">✓ Encryption ready</p>}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleCloseSecretChat}
            className="bg-red-500 hover:bg-red-600 text-white px-3 py-1 rounded text-sm"
            title="Close secret chat"
          >
            Close
          </button>
          <button
            onClick={handleClose}
            className="text-gray-500 hover:text-gray-700 text-2xl"
            title="Close window"
          >
            ✕
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.length === 0 ? (
          <p className="text-gray-500 text-center py-8">No messages yet</p>
        ) : (
          messages.map((message) => (
            <div
              key={message.id}
              className={`flex ${message.senderId === userId ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-xs px-4 py-2 rounded-lg ${
                  message.senderId === userId
                    ? message.isPending 
                      ? 'bg-blue-300 text-white opacity-75' 
                      : 'bg-blue-500 text-white'
                    : 'bg-gray-100 text-gray-800'
                }`}
              >
                {message.type === 'file' && message.fileName ? (
                  <div className="bg-white bg-opacity-10 rounded p-3 space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="text-lg">📎</span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold truncate">{message.fileName}</p>
                      </div>
                      {message.isPending && <span className="text-xs ml-auto">⏳</span>}
                    </div>
                    {message.decrypted && message.decrypted.startsWith('data:') ? (
                      <button
                        onClick={() => {
                          const link = document.createElement('a');
                          link.href = message.decrypted || '';
                          link.download = message.fileName || 'file';
                          document.body.appendChild(link);
                          link.click();
                          document.body.removeChild(link);
                        }}
                        className={`w-full text-center py-2 rounded text-xs font-medium transition ${
                          message.senderId === userId
                            ? 'bg-blue-400 hover:bg-blue-300 text-white'
                            : 'bg-gray-400 hover:bg-gray-500 text-white'
                        }`}
                      >
                        ⬇️ Download
                      </button>
                    ) : null}
                  </div>
                ) : (
                  <>
                    <p className="text-sm whitespace-pre-wrap break-words">
                      {message.decrypted || message.ciphertext.substring(0, 20) + '...'}
                    </p>
                    {message.isPending && (
                      <p className="text-xs mt-1 italic">
                        ⏳ sending...
                      </p>
                    )}
                  </>
                )}
                <p className="text-xs opacity-70 mt-1">
                  {message.timestamp instanceof Date
                    ? message.timestamp.toLocaleString()
                    : new Date(message.timestamp).toLocaleString()}
                </p>
              </div>
            </div>
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      {encryptProgress > 0 && (
        <div className="px-4 py-2 bg-gray-100">
          <p className="text-xs text-gray-600 mb-1">Encrypting: {encryptProgress}%</p>
          <div className="w-full bg-gray-300 rounded-full h-1">
            <div
              className="bg-blue-500 h-1 rounded-full transition-all duration-300"
              style={{ width: `${encryptProgress}%` }}
            />
          </div>
        </div>
      )}

      <form onSubmit={handleSendMessage} className="p-4 border-t border-gray-200 space-y-2">
        {error && (
          <div className="bg-red-100 border border-red-400 text-red-700 px-3 py-2 rounded text-sm">
            {error}
          </div>
        )}

        {!dhInitialized && (
          <div className="bg-yellow-100 border border-yellow-400 text-yellow-800 px-3 py-2 rounded text-sm">
            ⏳ Initializing encryption... {dhProgress && `(${dhProgress})`}
          </div>
        )}

        {selectedFile && (
          <div className="flex items-center gap-2 p-2 bg-gray-100 rounded">
            <span className="text-sm text-gray-700">📄 {selectedFile.name}</span>
            <button
              type="button"
              onClick={() => setSelectedFile(null)}
              className="ml-auto text-gray-500 hover:text-gray-700"
            >
              ✕
            </button>
          </div>
        )}

        <div className="flex gap-2">
          <input
            type="text"
            value={messageText}
            onChange={(e) => setMessageText(e.target.value)}
            placeholder="Type a message..."
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          />
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileSelect}
            className="hidden"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="bg-gray-500 hover:bg-gray-600 text-white px-3 py-2 rounded-lg transition"
            title="Attach file"
          >
            📎
          </button>
          <button
            type="submit"
            disabled={loading || !dhInitialized || (!messageText.trim() && !selectedFile)}
            className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
            title={!dhInitialized ? 'Waiting for encryption initialization...' : ''}
          >
            {loading ? '...' : 'Send'}
          </button>
        </div>
      </form>
    </div>
  );
};
