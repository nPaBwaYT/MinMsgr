import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { initWasmCrypto } from './wasm/cryptoWrapper'
import './index.css'

// Initialize WASM crypto module on app startup
initWasmCrypto().then(success => {
  if (success) {
    console.log('[Main] ✅ WASM crypto initialized successfully');
  } else {
    console.warn('[Main] ⚠️ WASM crypto initialization failed - app will use fallback XOR (NOT SECURE)');
  }
}).catch(err => {
  console.error('[Main] ❌ Unexpected error during WASM init:', err);
});

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
