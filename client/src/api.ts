import axios from 'axios';

const API_URL = 'http://localhost:8080/api';
const WS_URL = 'ws://localhost:8080/ws';

const client = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// WebSocket connection
let ws: WebSocket | null = null;
let wsSubscribers: Map<string, Set<(data: any) => void>> = new Map();
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 10;
const RECONNECT_DELAY = 1000; // 1 second, exponential backoff

// Add token to requests
client.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// WebSocket management
export const wsService = {
  connect: (token: string): Promise<void> => {
    return new Promise((resolve, reject) => {
      try {
        // Pass token as query parameter for WebSocket handshake
        const wsUrlWithToken = `${WS_URL}?token=${encodeURIComponent(token)}`;
        ws = new WebSocket(wsUrlWithToken);
        const connection = ws;
        
        connection.onopen = () => {
          console.log('[WS] Connected to server');
          reconnectAttempts = 0;
          resolve();
        };
        connection.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            const type = message.type || 'unknown';
            
            console.log('[WS] Received event:', type, message);
            
            // For message_received events, also route by chat_id
            if (type === 'message_received' && message.data && message.data.chat_id) {
              const chatKey = `message_${message.data.chat_id}`;
              console.debug('[WS] Routing message_received to channel:', chatKey, 'with data:', message.data);
              const chatSubscribers = wsSubscribers.get(chatKey);
              if (chatSubscribers) {
                console.debug(`[WS] Found ${chatSubscribers.size} subscriber(s) for ${chatKey}`);
                chatSubscribers.forEach(callback => {
                  console.debug('[WS] Calling subscriber for', chatKey);
                  callback(message.data);
                });
              } else {
                console.warn('[WS] No subscribers found for channel:', chatKey);
                console.log('[WS] Available channels:', Array.from(wsSubscribers.keys()));
              }
            }
            
            // Notify all subscribers for this event type
            const subscribers = wsSubscribers.get(type);
            if (subscribers) {
              console.debug(`[WS] Found ${subscribers.size} subscriber(s) for event type: ${type}`);
              subscribers.forEach(callback => callback(message));
            }
            
            // Also notify general subscribers
            const generalSubscribers = wsSubscribers.get('*');
            if (generalSubscribers) {
              generalSubscribers.forEach(callback => callback(message));
            }
          } catch (err) {
            console.error('Failed to parse WebSocket message:', err);
          }
        };
        connection.onerror = (error) => {
          console.error('[WS] WebSocket error:', error);
          reject(error);
        };
        connection.onclose = () => {
          console.log('[WS] WebSocket disconnected');
          ws = null;
          
          // Attempt to reconnect
          if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
            const delay = RECONNECT_DELAY * Math.pow(2, reconnectAttempts);
            reconnectAttempts++;
            console.log(`[WS] Attempting to reconnect in ${delay}ms (attempt ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})`);
            setTimeout(() => {
              wsService.connect(token).catch(err => {
                console.error('[WS] Reconnection failed:', err);
              });
            }, delay);
          } else {
            console.error('[WS] Max reconnection attempts reached');
          }
        };
      } catch (err) {
        reject(err);
      }
    });
  },

  disconnect: () => {
    if (ws) {
      ws.close();
      ws = null;
      reconnectAttempts = 0;
    }
  },

  subscribe: (eventType: string, callback: (data: any) => void) => {
    if (!wsSubscribers.has(eventType)) {
      wsSubscribers.set(eventType, new Set());
    }
    wsSubscribers.get(eventType)!.add(callback);
    
    return () => {
      const subscribers = wsSubscribers.get(eventType);
      if (subscribers) {
        subscribers.delete(callback);
      }
    };
  },

  isConnected: (): boolean => {
    return ws !== null && ws.readyState === WebSocket.OPEN;
  },
};

export interface LoginResponse {
  user_id: number;
  username: string;
  token: string;
  encrypted_private_key?: string;
}

export interface RegisterResponse {
  user_id: number;
  username: string;
}

export interface ChatResponse {
  chat_id: number;
  user1_id: number;
  user2_id: number;
  algorithm: string;
  mode: string;
  padding: string;
  created_at: string;
}

export interface MessageResponse {
  message_id: number;
  chat_id: number;
  sender_id: number;
  timestamp: string;
  status: string;
}

export const apiService = {
  // Authentication
  async register(username: string, password: string, publicKeyHex?: string, encryptedPrivateKeyHex?: string): Promise<RegisterResponse> {
    const body: any = { username, password };
    if (publicKeyHex) body.public_key = publicKeyHex;
    if (encryptedPrivateKeyHex) body.encrypted_private_key = encryptedPrivateKeyHex;
    const response = await client.post('/auth/register', body);
    return response.data;
  },

  async login(username: string, password: string): Promise<LoginResponse> {
    const response = await client.post('/auth/login', { username, password });
    return response.data;
  },

  async getGlobalDHParams(): Promise<any> {
    const response = await client.get('/dh/global');
    return response.data;
  },

  // Contacts
  async sendContactRequest(contactId: number, action: string = 'add'): Promise<any> {
    const response = await client.post('/contacts/request', {
      action,
      contact_id: contactId,
    });
    return response.data;
  },

  async getContacts(): Promise<any> {
    const response = await client.get('/contacts');
    return response.data;
  },

  async getPendingRequests(): Promise<any> {
    const response = await client.get('/contacts/pending');
    return response.data;
  },

  async acceptContact(contactId: number): Promise<any> {
    const response = await client.post('/contacts/request', {
      action: 'accept',
      contact_id: contactId,
    });
    return response.data;
  },

  async rejectContact(contactId: number): Promise<any> {
    const response = await client.post('/contacts/request', {
      action: 'reject',
      contact_id: contactId,
    });
    return response.data;
  },

  // Chats
  async createChat(
    user2Id: number,
    algorithm: string,
    mode: string,
    padding: string
  ): Promise<ChatResponse> {
    const response = await client.post('/chats/create', {
      user2_id: user2Id,
      algorithm,
      mode,
      padding,
    });
    
    // Check if server returned error in the response
    if (!response.data.success && response.data.error) {
      const error: any = new Error(response.data.error);
      error.response = { data: { error: response.data.error } };
      throw error;
    }
    
    return response.data;
  },

  async getChats(): Promise<any> {
    const response = await client.get(`/chats`);
    return response.data;
  },

  async closeChat(chatId: number): Promise<any> {
    const response = await client.post(`/chats/${chatId}/close`);
    return response.data;
  },

  async joinChat(chatId: number): Promise<any> {
    const response = await client.post(`/chats/${chatId}/join`);
    return response.data;
  },

  async leaveChat(chatId: number): Promise<any> {
    const response = await client.post(`/chats/${chatId}/leave`);
    return response.data;
  },

  // Messages
  async sendMessage(
    chatId: number,
    ciphertext: string,
    iv: string,
    fileName?: string,
    mimeType?: string
  ): Promise<MessageResponse> {
    const body: any = {
      chat_id: chatId,
      ciphertext,
      iv,
    };
    if (fileName) body.file_name = fileName;
    if (mimeType) body.mime_type = mimeType;
    const response = await client.post('/messages/send', body);
    return response.data;
  },

  async getMessages(chatId: number, limit: number = 100, offset: number = 0): Promise<any> {
    const response = await client.get(`/chats/${chatId}/messages`, {
      params: { limit, offset },
    });
    return response.data;
  },

  // Diffie-Hellman Key Exchange
  async initDHExchange(chatId: number): Promise<any> {
    const response = await client.post(`/chats/${chatId}/dh/init`);
    return response.data;
  },

  async completeDHExchange(chatId: number, publicKeyHex: string): Promise<any> {
    const response = await client.post(`/chats/${chatId}/dh/exchange`, {
      public_key: publicKeyHex,
    });
    return response.data;
  },

  async getUserPublicKey(userId: number): Promise<any> {
    const response = await client.get(`/users/${userId}/public-key`);
    return response.data;
  },

  async getMyPublicKey(): Promise<any> {
    const response = await client.get(`/me/public-key`);
    return response.data;
  },
};

export default apiService;
