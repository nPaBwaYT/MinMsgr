# MinMessenger Client

A React-based web client for the MinMessenger encrypted messaging platform.

## Features

- **User Authentication**: Register and login with secure password handling
- **Contact Management**: Add, remove, and manage contacts
- **Secret Chats**: Create encrypted chat rooms with algorithm selection
- **Encryption**: Client-side encryption/decryption with progress tracking
- **Message History**: Local storage of messages using IndexedDB
- **File Support**: Send and receive encrypted files
- **Real-time Updates**: WebSocket integration for live message delivery
- **Progress Tracking**: Visual progress bars for encryption/decryption operations
- **Responsive UI**: Beautiful Tailwind CSS design

## Requirements

- Node.js 16+
- npm or yarn

## Installation

```bash
cd client
npm install
```

## Development

```bash
npm run dev
```

The client will be available at `http://localhost:3000`

### Optional: Build Go -> WASM encryption module

You can compile the server's Go encryption package to WebAssembly and let the client use the native Go implementations from the browser.

Steps (Windows PowerShell example):

1. Copy the Go runtime support file to client public:

```powershell
copy $(go env GOROOT)\misc\wasm\wasm_exec.js d:\Projects\MinMessanger\client\public\wasm_exec.js
```

2. Build the encryption package as WASM (run from `server` folder):

```powershell
set GOOS=js
set GOARCH=wasm
go build -o ..\client\public\crypto.wasm ./internal/pkg/encryption
```

3. Ensure `wasm_exec.js` is included in `index.html` before the client bundle (example):

```html
<script src="/wasm_exec.js"></script>
<script type="module" src="/src/main.tsx"></script>
```

4. Run server and client; the client will try to initialize the WASM module at `/crypto.wasm`.

Notes:
- The Go package should register a global `WasmCrypto` object exposing `Encrypt` and `Decrypt` helper functions (or similar) so the JS wrapper can call them. See `COMPLETE_SETUP.md` for suggested code snippets.
- If WASM is unavailable, the client falls back to a JS demo implementation.

## Build

```bash
npm run build
```

Output will be in the `dist` directory.

## Configuration

Update the API server address in `src/api.ts`:

```typescript
const API_URL = 'http://localhost:8080/api';
```

## Project Structure

```
src/
├── components/
│   ├── LoginPage.tsx       # Authentication UI
│   ├── ContactManager.tsx  # Contact management
│   ├── ChatSelector.tsx    # Chat selection and creation
│   └── ChatWindow.tsx      # Main chat interface
├── api.ts                  # API client service
├── crypto.ts               # Encryption utilities
├── db.ts                   # Local database (Dexie)
├── App.tsx                 # Main app component
├── main.tsx                # Entry point
└── index.css               # Global styles
```

## Security Notes

- Passwords are sent via HTTPS in production
- Encryption/decryption happens on the client-side
- Session keys are managed securely
- Messages are stored encrypted locally

## Browser Support

- Chrome/Chromium 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Technologies

- **React 18**: UI framework
- **TypeScript**: Type-safe development
- **Tailwind CSS**: Styling
- **Axios**: HTTP client
- **Dexie**: IndexedDB wrapper
- **Vite**: Build tool

## Usage

1. Register a new account or login
2. Add contacts by their user ID
3. Create a secret chat with a contact
4. Choose encryption algorithm, mode, and padding
5. Send encrypted messages
6. Messages are automatically decrypted and displayed

## License

MIT
