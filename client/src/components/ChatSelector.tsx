import React, { useState, useEffect } from 'react';
import apiService, { wsService } from '../api';
import { Chat } from '../db';

interface ChatSelectorProps {
  userId: number;
  onSelectChat: (chat: Chat) => void;
  onCreateChat: (chat: Chat) => void;
}

const ALGORITHMS = ['LOKI97', 'RC6'];
const MODES = ['ECB', 'CBC', 'PCBC', 'CFB', 'OFB', 'CTR', 'RandomDelta'];
const PADDINGS = ['ZEROS', 'PKCS7', 'ANSIX923', 'ISO10126'];

export const ChatSelector: React.FC<ChatSelectorProps> = ({
  userId,
  onSelectChat,
  onCreateChat,
}) => {
  const [chats, setChats] = useState<Chat[]>([]);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [selectedAlgorithm, setSelectedAlgorithm] = useState('LOKI97');
  const [selectedMode, setSelectedMode] = useState('CBC');
  const [selectedPadding, setSelectedPadding] = useState('PKCS7');
  const [targetUserId, setTargetUserId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    loadChats();
    
    // Subscribe to all events for debugging
    const unsubscribe = wsService.subscribe('*', (event: any) => {
      console.log('[ChatSelector] Received event:', event.type, event);
      
      // Handle chat creation events
      if (event.type === 'chat_created') {
        console.log('[ChatSelector] New chat created, reloading chats...');
        loadChats();
      }
      
      // Handle any chat-related events
      if (event.type?.includes('chat')) {
        console.log('[ChatSelector] Chat event detected, reloading chats...');
        loadChats();
      }
      
      // Handle message events to trigger chat reload
      if (event.type === 'message_received') {
        console.log('[ChatSelector] Message received in chat, reloading...');
        loadChats();
      }
    });

    return unsubscribe;
  }, [userId]);

  const loadChats = async () => {
    try {
      const response = await apiService.getChats();
      const transformedChats = response.chats?.map((c: any) => {
        const chat: Chat = {
          id: c.ID || c.id || c.chat_id,
          user1Id: c.User1ID || c.user1_id,
          user2Id: c.User2ID || c.user2_id,
          algorithm: c.Algorithm || c.algorithm,
          mode: c.Mode || c.mode,
          padding: c.Padding || c.padding,
          createdAt: new Date(c.CreatedAt ? c.CreatedAt * 1000 : c.created_at),
        };
        console.debug('[ChatSelector] Loaded chat:', chat);
        return chat;
      }) || [];
      setChats(transformedChats);
      setError('');
    } catch (err) {
      console.error('[ChatSelector] Failed to load chats:', err);
      setError('Failed to load chats');
    }
  };

  const handleCreateChat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUserId.trim()) return;

    setLoading(true);
    try {
      const response = await apiService.createChat(
        parseInt(targetUserId),
        selectedAlgorithm,
        selectedMode,
        selectedPadding
      );

      const newChat: Chat = {
        id: response.chat_id,
        user1Id: response.user1_id,
        user2Id: response.user2_id,
        algorithm: response.algorithm,
        mode: response.mode,
        padding: response.padding,
        createdAt: new Date(response.created_at),
      };

      setChats([...chats, newChat]);
      onCreateChat(newChat);
      setShowCreateForm(false);
      setTargetUserId('');
      setError('');
    } catch (err: any) {
      const errorMsg = err.response?.data?.error || 'Failed to create chat';
      console.error('[ChatSelector] Create chat error:', errorMsg);
      
      // Provide user-friendly messages for specific errors
      if (errorMsg.includes('not in your contacts')) {
        setError('This user is not in your contacts. Add them first.');
      } else if (errorMsg.includes('accepted')) {
        setError('You must accept their contact request first.');
      } else if (errorMsg.includes('active chat')) {
        setError('You already have an active chat with this user.');
      } else {
        setError(errorMsg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold text-gray-800">Secret Chats</h2>
        <button
          onClick={() => setShowCreateForm(!showCreateForm)}
          className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg transition"
        >
          {showCreateForm ? 'Cancel' : '+ New Chat'}
        </button>
      </div>

      {showCreateForm && (
        <form onSubmit={handleCreateChat} className="mb-6 p-4 bg-gray-50 rounded-lg space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Contact User ID
            </label>
            <input
              type="number"
              value={targetUserId}
              onChange={(e) => setTargetUserId(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg"
              placeholder="Enter user ID"
              required
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Algorithm
              </label>
              <select
                value={selectedAlgorithm}
                onChange={(e) => setSelectedAlgorithm(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg"
              >
                {ALGORITHMS.map((algo) => (
                  <option key={algo} value={algo}>
                    {algo}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Mode
              </label>
              <select
                value={selectedMode}
                onChange={(e) => setSelectedMode(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg"
              >
                {MODES.map((mode) => (
                  <option key={mode} value={mode}>
                    {mode}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Padding
              </label>
              <select
                value={selectedPadding}
                onChange={(e) => setSelectedPadding(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg"
              >
                {PADDINGS.map((pad) => (
                  <option key={pad} value={pad}>
                    {pad}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-3 py-2 rounded text-sm">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
          >
            {loading ? 'Creating...' : 'Create Chat'}
          </button>
        </form>
      )}

      <div className="space-y-2 max-h-96 overflow-y-auto">
        {chats.length === 0 ? (
          <p className="text-gray-500 text-center py-4">No chats yet</p>
        ) : (
          chats.map((chat) => (
            <button
              key={chat.id}
              onClick={() => onSelectChat(chat)}
              className="w-full text-left p-3 bg-gray-50 hover:bg-blue-100 rounded-lg transition border-l-4 border-blue-500"
            >
              <p className="font-medium text-gray-800">
                Chat with User {chat.user1Id === userId ? chat.user2Id : chat.user1Id}
              </p>
              <p className="text-xs text-gray-500">
                {chat.algorithm} • {chat.mode} • {chat.padding}
              </p>
            </button>
          ))
        )}
      </div>
    </div>
  );
};
