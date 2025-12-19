import { useState, useEffect } from 'react';
import { LoginPage } from './components/LoginPage';
import { ContactManager } from './components/ContactManager';
import { ChatSelector } from './components/ChatSelector';
import { ChatWindow } from './components/ChatWindow';
import type { Chat } from './db';
import { wsService } from './api';
import './index.css';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userId, setUserId] = useState<number | null>(null);
  const [username, setUsername] = useState('');
  const [selectedChat, setSelectedChat] = useState<Chat | null>(null);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const storedUserId = localStorage.getItem('userId');
    const storedUsername = localStorage.getItem('username');

    if (token && storedUserId && storedUsername) {
      setIsLoggedIn(true);
      setUserId(parseInt(storedUserId));
      setUsername(storedUsername);
      // Connect to WebSocket
      wsService.connect(token).catch(err => {
        console.error('Failed to connect to WebSocket:', err);
      });
    }
  }, []);

  const handleLoginSuccess = (newUserId: number, newUsername: string, token: string) => {
    setIsLoggedIn(true);
    setUserId(newUserId);
    setUsername(newUsername);
    localStorage.setItem('userId', newUserId.toString());
    localStorage.setItem('username', newUsername);
    localStorage.setItem('token', token);
    // Connect to WebSocket
    wsService.connect(token).catch(err => {
      console.error('Failed to connect to WebSocket:', err);
    });
  };

  const handleLogout = () => {
    console.log('[App] Logout initiated, clearing all localStorage keys...');
    setIsLoggedIn(false);
    setUserId(null);
    setUsername('');
    setSelectedChat(null);
    // Clear all authentication and DH keys
    localStorage.removeItem('token');
    localStorage.removeItem('userId');
    localStorage.removeItem('username');
    localStorage.removeItem('dh_private_key');
    localStorage.removeItem('encrypted_private_key');
    console.log('[App] ✓ Cleared token, userId, username, dh_private_key, encrypted_private_key from localStorage');
    // Disconnect WebSocket
    wsService.disconnect();
  };

  if (!isLoggedIn) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-blue-600">MinMessenger</h1>
            <p className="text-sm text-gray-600">Welcome, {username} (ID: {userId})</p>
          </div>
          <button
            onClick={handleLogout}
            className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg transition"
          >
            Logout
          </button>
        </div>
      </div>

      {/* Main content */}
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Sidebar */}
          <div className="lg:col-span-1 space-y-6">
            {userId && (
              <>
                <ContactManager userId={userId} onSelectContact={() => {}} />
              </>
            )}
          </div>

          {/* Main area */}
          <div className="lg:col-span-3 space-y-6">
            {selectedChat ? (
              <ChatWindow
                userId={userId!}
                chat={selectedChat}
                onClose={() => setSelectedChat(null)}
              />
            ) : userId ? (
              <ChatSelector
                userId={userId}
                onSelectChat={setSelectedChat}
                onCreateChat={(newChat: Chat) => {
                  // Auto-select newly created chat
                  setSelectedChat(newChat);
                }}
              />
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
