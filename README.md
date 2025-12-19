# MinMessanger - Secure End-to-End Encrypted Messaging

**MinMessanger** — это полнофункциональное приложение для отправки защищённых сообщений между пользователями с поддержкой двух симметричных алгоритмов шифрования (RC6 и LOKI97), протокола Диффи-Хеллмана для обмена ключами и современной архитектуры клиент-сервер.

> 🔧 **ВАЖНО: Все проблемы исправлены!**  
> - ✅ WASM криптография на клиенте работает безопасно (не XOR fallback)
> - ✅ Контакты загружаются без ошибок Dexie
> - ✅ Локальная база данных синхронизирована
> - ✅ importObject обработан для старых и новых версий wasm_exec.js
> 
> **БЫСТРЫЙ СТАРТ (3 команды):**
> ```bash
> rebuild-final.bat             # Пересобрать всё (WASM + клиент)
> cd client && npm run dev      # Запустить dev сервер
> # Открыть http://localhost:5173 и проверить консоль на ✅ логи
> ```
> 
> **Подробнее:** [FINAL_INSTRUCTIONS.txt](FINAL_INSTRUCTIONS.txt), [FIXES_SUMMARY.md](FIXES_SUMMARY.md)

## 🎯 Особенности

- ✅ **End-to-End Encryption**: Все сообщения шифруются на клиенте перед отправкой на сервер
- ✅ **Dual Algorithm Support**: RC6 и LOKI97 - два симметричных алгоритма на выбор
- ✅ **Key Exchange Protocol**: Диффи-Хеллман 2048-bit (RFC 3526) для безопасного обмена ключами
- ✅ **Real-time Communication**: WebSocket для real-time доставки сообщений
- ✅ **User Authentication**: JWT-токены + bcrypt хеширование паролей
- ✅ **Contact Management**: Система добавления/удаления контактов с запросами
- ✅ **File Support**: Отправка файлов (текст, изображения, etc.)
- ✅ **Responsive UI**: React + TypeScript + Tailwind CSS
- ✅ **WebAssembly Crypto**: Криптография выполняется в WASM на клиенте (безопасно)

---

## 🏗️ Архитектура

### Система компонентов

```
┌─────────────────────────────────────────────────────────────┐
│                    React Client (3000)                      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  LoginPage | ContactManager | ChatSelector | etc.    │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Crypto Layer (RC6, LOKI97, DH, Key Derivation)      │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │ REST API + WebSocket
                       ↓
┌─────────────────────────────────────────────────────────────┐
│              Go Gateway Server (8080)                       │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Auth | Contacts | Chats | Messages Services         │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  DH Protocol | Crypto Verification | JWT Validation  │   │
│  └──────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  WebSocket Hub (Real-time Broadcasting)              │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │ SQL
                       ↓
            ┌──────────────────────┐
            │   PostgreSQL (5432)  │
            │   minmsgr database   │
            └──────────────────────┘
```

### Поток шифрования сообщения

```
1. Client: Выбирает алгоритм (RC6/LOKI97), режим (CBC), набивку (PKCS7)
2. Client: Генерирует IV (Initialization Vector)
3. Client: Вычисляет shared secret через DH с публичным ключом собеседника
4. Client: Производит PBKDF2(password, salt) → 256-bit ключ
5. Client: Шифрует сообщение: E(message, key, IV) → ciphertext
6. Client: Отправляет {ciphertext, IV, algorithm, mode, padding} на сервер
7. Server: Сохраняет в БД
8. Server: Рассылает WebSocket подписчикам
9. Client (получатель): Получает зашифрованные данные
10. Client: Вычисляет тот же shared secret (DH симметричен)
11. Client: Производит PBKDF2 с тем же паролем
12. Client: Расшифровывает: D(ciphertext, key, IV) → message
```

---

## 🔐 Криптографическая архитектура

### 1. Алгоритмы шифрования

| Алгоритм   | Размер блока | Размер ключа |    Реализация     |
|------------|--------------|--------------|-------------------|
| **RC6**    |    128 бит   | 128-256 бит  | Custom TypeScript |
| **LOKI97** |    128 бит   | 128-256 бит  | Custom TypeScript |

### 2. Режимы шифрования

- ✅ **CBC** (Cipher Block Chaining) - реализован
- ⏳ Планируется: ECB, PCBC, CFB, OFB, CTR, Random Delta

### 3. Режимы набивки

- ✅ **Zeros** - переработан (правильная реализация)
- ⏳ Планируется: ANSI X.923, PKCS7, ISO 10126

### 4. Обмен ключами: Diffie-Hellman

```
Client A                           Server                      Client B
   │                                  │                            │
   ├─────── generatePrivateKey() ────>│<─── generatePrivateKey() ──┤
   │         (BigInt random)          │      (BigInt random)       │
   │                                  │                            │
   ├─────── getPublicKey() ──────────>│<───── getPublicKey() ──────┤
   │ Pub_A = g^a mod p (256 bytes)    │ Pub_B = g^b mod p (256)    │
   │                                  │                            │
   ├────────── Exchange via API ─────────────────────────────────→ │
   │ {algorithm, pubKey_A, p, g}      │  {algorithm, pubKey_B}     │
   │                                  │                            │
   ├─ computeSharedSecret(Pub_B) ────>│<─ computeSharedSecret()    │
   │ Shared = Pub_B^a mod p (256)     │ Shared = Pub_A^b mod p     │
   │                                  │                            │
```

**Параметры RFC 3526**:
- Prime `p`: 2048-bit
- Generator `g`: 2 (стандартный)
- Все значения: **256 bytes** (2048 bits) для консистентности

### 5. Хеширование паролей

```
Password Registration:
  password + random_salt → bcrypt(cost=12) → hash
  
Login Verification:
  password + stored_hash → bcrypt.Compare() → ✅ or ❌
```

**Безопасность**:
- Автоматическая генерация соли
- Адаптивное хеширование (медленно, защита от brute-force)
- Соответствует OWASP стандартам

### 6. Производство ключей

```
Key Derivation:
  password → PBKDF2 (SHA-256, 100K iterations) → 256-bit key
  
Используется для:
  - Шифрования приватного ключа DH (AES-GCM)
  - Симметричного ключа для сообщений (совместно с shared secret)
```

---

## 🖼️ Структура проекта

```
MinMessanger/
│
├── client/                         # React TypeScript фронтенд
│   ├── src/
│   │   ├── App.tsx                # Главный компонент
│   │   ├── api.ts                 # Axios клиент, WebSocket
│   │   ├── crypto.ts              # Криптография (RC6, LOKI97, DH)
│   │   ├── db.ts                  # IndexedDB локальное хранилище
│   │   ├── components/            # React компоненты
│   │   │   ├── LoginPage.tsx      # Регистрация/вход
│   │   │   ├── ChatWindow.tsx     # Окно чата
│   │   │   ├── ContactManager.tsx # Управление контактами
│   │   │   └── ...
│   │   └── __tests__/             # Тесты
│   ├── vite.config.ts             # Vite конфигурация + прокси
│   ├── tailwind.config.js         # Tailwind CSS
│   └── package.json
│
├── server/                        # Go бэкенд
│   ├── cmd/
│   │   └── gateway/
│   │       └── main.go            # Точка входа
│   │
│   ├── internal/
│   │   ├── api/
│   │   │   └── gateway/
│   │   │       └── gateway.go     # HTTP маршруты, WebSocket hub
│   │   │
│   │   ├── services/
│   │   │   ├── auth/              # Аутентификация (bcrypt, JWT)
│   │   │   ├── chat/              # Управление чатами, DH
│   │   │   ├── contact/           # Управление контактами
│   │   │   └── message/           # Обработка сообщений
│   │   │
│   │   ├── storage/
│   │   │   ├── postgres.go        # Инициализация БД
│   │   │   └── db.go              # SQL операции
│   │   │
│   │   ├── pkg/
│   │   │   ├── crypto/
│   │   │   │   └── diffie_hellman.go  # DH реализация (Go)
│   │   │   ├── config/
│   │   │   │   └── config.go      # Конфигурация из env
│   │   │   └── protocol/
│   │   │       └── messages.go    # Структуры данных
│   │   │
│   │   └── protocol/
│   │       └── *.go               # Общие структуры
│   │
│   ├── go.mod                     # Go зависимости
│   └── go.sum
│
├── docker-compose.yml             # Docker контейнеры
├── Dockerfile.gateway             # Build сервера
│
└── README.md                      # Этот файл
```

---

## 🚀 Быстрый старт

### Требования

- **Node.js** 18+ (клиент)
- **Go** 1.21+ (сервер)
- **PostgreSQL** 15+ (БД)
- **Docker** (опционально)

### Локальный запуск (без Docker)

#### 1️⃣ Подготовка БД

```bash
# Создать БД
createdb minmsgr

# Применить миграции (сервер создаст схему автоматически)
```

#### 2️⃣ Запуск сервера

```bash
cd d:\Projects\MinMessanger\server

# Установить зависимости Go
go mod download

# Запустить сервер (слушает на :8080)
go run ./cmd/gateway
```

Ожидаемый вывод:
```
[Database] Connected to minmsgr
[Database] Schema initialized
Global DH parameters initialized (p length=256, g length=256)
Gateway server listening on :8080
```

#### 3️⃣ Запуск клиента

```bash
cd d:\Projects\MinMessanger\client

# Установить зависимости Node
npm install

# Запустить dev сервер (на :3000, прокси на :8080)
npm run dev
```

Откройте **http://localhost:3000** в браузере.

### Docker Compose (рекомендуется для продакшена)

```bash
cd d:\Projects\MinMessanger

# Собрать и запустить контейнеры
docker compose build
docker compose up -d

# Сервер: http://localhost:8080
# Клиент: http://localhost:3000 (требуется отдельный npm run dev)
```

---

## 📡 REST API

### Аутентификация

#### POST `/api/auth/register`

Регистрация нового пользователя.

```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "securepass123",
    "public_key_hex": "a1b2c3d4...",
    "encrypted_private_key_hex": "e5f6g7h8..."
  }'
```

**Ответ (200)**:
```json
{
  "user_id": 1,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "encrypted_private_key_hex": "e5f6g7h8..."
}
```

#### POST `/api/auth/login`

Вход в учетную запись.

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "securepass123"
  }'
```

**Ответ (200)**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "encrypted_private_key_hex": "e5f6g7h8..."
}
```

### Контакты

#### GET `/api/contacts`

Получить список принятых контактов.

```bash
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:8080/api/contacts
```

**Ответ (200)**:
```json
[
  {
    "id": 2,
    "user_id": 1,
    "contact_id": 2,
    "contact_username": "bob",
    "status": "accepted",
    "created_at": 1703000000
  }
]
```

#### POST `/api/contacts/request`

Добавить контакт / Принять / Отклонить запрос.

```bash
# Добавить контакт
curl -X POST http://localhost:8080/api/contacts/request \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "contact_id": 2,
    "action": "add"
  }'

# Принять запрос
curl -X POST http://localhost:8080/api/contacts/request \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "contact_id": 3,
    "action": "accept"
  }'
```

#### GET `/api/contacts/pending`

Получить ожидающие запросы контактов.

```bash
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:8080/api/contacts/pending
```

### Чаты

#### POST `/api/chats/create`

Создать новый чат.

```bash
curl -X POST http://localhost:8080/api/chats/create \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user1_id": 1,
    "user2_id": 2,
    "algorithm": "RC6",
    "mode": "CBC",
    "padding": "PKCS7"
  }'
```

**Ответ (200)**:
```json
{
  "chat_id": 1,
  "status": "created"
}
```

#### GET `/api/chats`

Получить все чаты пользователя.

```bash
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:8080/api/chats
```

#### POST `/api/chats/{chatID}/close`

Закрыть чат (только создатель).

```bash
curl -X POST http://localhost:8080/api/chats/1/close \
  -H "Authorization: Bearer TOKEN"
```

### Диффи-Хеллман (DH)

#### GET `/api/dh/global`

Получить глобальные параметры DH (p, g).

```bash
curl http://localhost:8080/api/dh/global
```

**Ответ (200)**:
```json
{
  "p_hex": "ffffffffffffffffc90fdaa22168c234...",
  "g_hex": "02"
}
```

#### POST `/api/chats/{chatID}/dh/init`

Инициировать обмен DH (отправить публичный ключ).

```bash
curl -X POST http://localhost:8080/api/chats/1/dh/init \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "public_key_hex": "a1b2c3d4e5f6g7h8i9j0...",
    "algorithm": "RC6"
  }'
```

#### POST `/api/chats/{chatID}/dh/exchange`

Завершить обмен DH (получить публичный ключ второго пользователя).

```bash
curl -X POST http://localhost:8080/api/chats/1/dh/exchange \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1
  }'
```

**Ответ (200)**:
```json
{
  "other_user_id": 2,
  "other_user_public_key_hex": "f6e5d4c3b2a1...",
  "p_hex": "ffffffffffffffffc90fdaa...",
  "g_hex": "02"
}
```

### Сообщения

#### POST `/api/messages/send`

Отправить зашифрованное сообщение.

```bash
curl -X POST http://localhost:8080/api/messages/send \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "chat_id": 1,
    "sender_id": 1,
    "ciphertext_hex": "3a5b7c9d...",
    "iv_hex": "1f2a3b4c5d6e7f8g9h0i",
    "file_name": "message.txt",
    "mime_type": "text/plain"
  }'
```

**Ответ (200)**:
```json
{
  "message_id": 42,
  "timestamp": 1703000000
}
```

#### GET `/api/chats/{chatID}/messages`

Получить все сообщения из чата.

```bash
curl -H "Authorization: Bearer TOKEN" \
  "http://localhost:8080/api/chats/1/messages?limit=50&offset=0"
```

**Ответ (200)**:
```json
[
  {
    "message_id": 1,
    "chat_id": 1,
    "sender_id": 1,
    "ciphertext_hex": "3a5b7c9d...",
    "iv_hex": "1f2a3b4c5d6e7f8g9h0i",
    "timestamp": 1703000000
  }
]
```

---

## 🔌 WebSocket

### Подключение

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = () => {
  // Отправить токен авторизации
  ws.send(JSON.stringify({
    type: 'auth',
    token: localStorage.getItem('token')
  }));
};

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  console.log('Received:', msg);
  // type: 'chat_created', 'message', 'contact_request', etc.
};
```

### События

| Событие | Описание | Payload |
|---------|---------|---------|
| `chat_created` | Новый чат создан | `{chat_id, user1_id, user2_id}` |
| `message` | Новое сообщение | `{message_id, chat_id, sender_id, ciphertext_hex, iv_hex, timestamp}` |
| `contact_request` | Новый запрос контакта | `{requester_id, contact_id}` |
| `contact_accepted` | Контакт принят | `{user_id, contact_id}` |
| `chat_closed` | Чат закрыт | `{chat_id, closed_by}` |

---

## 🔒 Безопасность

### Аутентификация
- ✅ JWT токены (24-часовой срок действия)
- ✅ bcrypt хеширование паролей (cost=12)
- ✅ Токены в localStorage (клиент) / Authorization header (запросы)

### Шифрование
- ✅ End-to-End: сообщения шифруются на клиенте
- ✅ Forward Secrecy: каждое сообщение имеет свой IV
- ✅ DH 2048-bit: обмен ключами без раскрытия приватных ключей
- ✅ AES-GCM: шифрование приватного ключа на клиенте

### Хранение ключей
- ✅ **Приватный ключ DH**: зашифрован на клиенте, хранится в localStorage
- ✅ **Публичный ключ DH**: сохранён на сервере, открыт для обмена
- ✅ **Пароль**: хеш на сервере, никогда не передаётся

### CORS и прочее
- ✅ CORS headers во всех ответах
- ✅ OPTIONS запросы для preflight
- ✅ Content-Type validation

---

## 📊 Схема БД

```sql
-- Пользователи
CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  hashed_password VARCHAR(255) NOT NULL,
  public_key BYTEA,
  encrypted_private_key BYTEA,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

-- Контакты (нормализованная: user1_id < user2_id)
CREATE TABLE contacts (
  id BIGSERIAL PRIMARY KEY,
  user1_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user2_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  requester_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  UNIQUE(user1_id, user2_id),
  CHECK(user1_id < user2_id)
);

-- Чаты
CREATE TABLE chats (
  id BIGSERIAL PRIMARY KEY,
  user1_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user2_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  algorithm VARCHAR(50) NOT NULL,
  mode VARCHAR(50) NOT NULL,
  padding VARCHAR(50) NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  created_at BIGINT NOT NULL,
  closed_at BIGINT,
  updated_at BIGINT NOT NULL,
  UNIQUE(user1_id, user2_id)
);

-- Глобальные параметры Диффи-Хеллмана
CREATE TABLE dh_globals (
  id BIGSERIAL PRIMARY KEY,
  p BYTEA NOT NULL,  -- 2048-bit prime (256 bytes)
  g BYTEA NOT NULL,  -- 2 (стандартный generator)
  created_at BIGINT NOT NULL
);

-- Параметры DH для каждого чата
CREATE TABLE dh_parameters (
  id BIGSERIAL PRIMARY KEY,
  chat_id BIGINT NOT NULL UNIQUE REFERENCES chats(id) ON DELETE CASCADE,
  p BYTEA NOT NULL,
  g BYTEA NOT NULL,
  created_at BIGINT NOT NULL
);

-- Публичные ключи DH участников
CREATE TABLE dh_public_keys (
  id BIGSERIAL PRIMARY KEY,
  chat_id BIGINT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key BYTEA NOT NULL,
  created_at BIGINT NOT NULL,
  UNIQUE(chat_id, user_id)
);

-- Ключи сессии (один на чат)
CREATE TABLE session_keys (
  id BIGSERIAL PRIMARY KEY,
  chat_id BIGINT NOT NULL UNIQUE REFERENCES chats(id) ON DELETE CASCADE,
  session_key BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  created_at BIGINT NOT NULL
);

-- Сообщения
CREATE TABLE messages (
  id BIGSERIAL PRIMARY KEY,
  chat_id BIGINT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
  sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ciphertext BYTEA NOT NULL,
  iv BYTEA NOT NULL,
  file_name VARCHAR(255),
  mime_type VARCHAR(100),
  created_at BIGINT NOT NULL
);

-- Индексы для производительности
CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);
CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_chats_user1_id ON chats(user1_id);
CREATE INDEX IF NOT EXISTS idx_chats_user2_id ON chats(user2_id);
CREATE INDEX IF NOT EXISTS idx_contacts_user1_id ON contacts(user1_id);
CREATE INDEX IF NOT EXISTS idx_contacts_user2_id ON contacts(user2_id);
```

**Ключевые особенности схемы**:
- Все таблицы с ON DELETE CASCADE для целостности данных
- Нормализация контактов: `user1_id < user2_id` (одна запись на пару)
- Уникальные индексы на чаты по парам пользователей
- Отдельная таблица для хранения публичных ключей DH
- Глобальные параметры DH (RFC 3526 2048-bit)
- Сессионные ключи для каждого чата

---

## 🧪 Тестирование

### Клиент (Jest + React Testing Library)

```bash
cd client

# Запустить все тесты
npm test

# Тесты криптографии
npm test crypto
```

### Сервер (Go testing)

```bash
cd server

# Все тесты
go test ./...

# Конкретный пакет
go test ./internal/services/auth -v

# С покрытием
go test ./... -cover
```

---

## 📝 Пример использования

### Регистрация и отправка сообщения

```typescript
// 1. Регистрация
const registerResp = await api.post('/auth/register', {
  username: 'alice',
  password: 'securepass123'
});

const token = registerResp.data.token;
localStorage.setItem('token', token);

// 2. Инициировать DH
const dhResp = await api.post('/dh/global', {});
const p = dhResp.data.p_hex;
const g = dhResp.data.g_hex;

const dh = new DiffieHellman(2048, p, g);
dh.generatePrivateKey();
const myPublicKey = dh.getPublicKey();

// 3. Создать чат
const chatResp = await api.post('/chats/create', {
  user1_id: 1,
  user2_id: 2,
  algorithm: 'RC6',
  mode: 'CBC',
  padding: 'PKCS7'
});

const chatId = chatResp.data.chat_id;

// 4. Обменяться публичными ключами
await api.post(`/chats/${chatId}/dh/init`, {
  user_id: 1,
  public_key_hex: myPublicKey,
  algorithm: 'RC6'
});

const exchangeResp = await api.post(`/chats/${chatId}/dh/exchange`, {
  user_id: 1
});

const otherPublicKey = exchangeResp.data.other_user_public_key_hex;

// 5. Вычислить shared secret
const sharedSecret = dh.computeSharedSecret(otherPublicKey);

// 6. Зашифровать сообщение
const message = 'Hello Bob!';
const iv = crypto.getRandomValues(new Uint8Array(16));
const rc6 = new RC6(256);
const encrypted = rc6.encrypt(message, sharedSecret, iv, 'CBC', 'PKCS7');

// 7. Отправить
await api.post('/messages/send', {
  chat_id: chatId,
  sender_id: 1,
  ciphertext_hex: encrypted,
  iv_hex: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('')
});

// 8. Получить через WebSocket
const ws = new WebSocket('ws://localhost:8080/ws');
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.type === 'message') {
    const ciphertext = Buffer.from(msg.ciphertext_hex, 'hex');
    const iv = Buffer.from(msg.iv_hex, 'hex');
    const decrypted = rc6.decrypt(ciphertext, sharedSecret, iv, 'CBC', 'PKCS7');
    console.log('Received:', decrypted);
  }
};
```

---

## 🐛 Troubleshooting

### Ошибка: "ERR_CONNECTION_REFUSED на localhost:3000"

**Причина**: WebSocket или REST запрос идёт на неправильный адрес.

**Решение**:
```bash
# Убедитесь, что сервер запущен на :8080
go run ./server/cmd/gateway

# Проверьте URL в api.ts
const API_URL = 'http://localhost:8080/api';
const WS_URL = 'ws://localhost:8080/ws';
```

### Ошибка: "Shared secret length: 128"

**Причина**: Ключи DH не паддировались правильно.

**Решение**: Код уже исправлен! Все ключи теперь **256 bytes**.

### Ошибка: "Password hash mismatch"

**Причина**: bcrypt хеш не совпадает (пароль неправильный или старый SHA256 хеш).

**Решение**: 
- Пересоздайте учётную запись (система теперь использует bcrypt)
- Или очистите БД: `DROP TABLE users; DROP TABLE contacts; DROP TABLE chats;`

### Ошибка: "CORS policy block"

**Причина**: Сервер не отправляет нужные CORS заголовки.

**Решение**: Убедитесь, что corsMiddleware применяется к маршрутизатору:
```go
return http.ListenAndServe(s.addr, corsMiddleware(router))
```

---

## 📚 Документация

- **API**: [REST API Reference](API_REFERENCE.md)
- **Криптография**: [DH Protocol](DH_PROTOCOL.md)
- **Требования**: [Project Requirements](REQUIREMENTS_CHECKLIST.md)
- **Аудит**: [Code Audit](CODE_AUDIT_REPORT.json)

---

## 📄 Лицензия

MIT License - свободно используйте и модифицируйте.

---

## 👥 Автор

Реализовано как полнофункциональное приложение для безопасной передачи сообщений с поддержкой end-to-end шифрования.

**Статус проекта**: ✅ Функционален, все критические компоненты готовы к использованию.

---

## 🎯 Статус реализации

| Компонент | Статус | Примечание |
|-----------|--------|-----------|
| RC6 + LOKI97 | ✅ Готово | Оба алгоритма (256-bit ключи), PKCS7 padding |
| Диффи-Хеллман | ✅ Готово | RFC 3526, 2048-bit (256 bytes), padding фикс |
| CBC режим | ✅ Готово | Основной режим работает с PKCS7 |
| ECB режим | ✅ Готово | Реализован для совместимости |
| Другие режимы | ⏳ Планируется | PCBC, CFB, OFB, CTR, Random Delta |
| JWT Authentication | ✅ Готово | 24-часовой срок действия |
| bcrypt Hashing | ✅ Готово | Password hashing (cost=12), заменил SHA256 |
| Contact Management | ✅ Готово | Добавление, принятие, отклонение, удаление |
| Chat Management | ✅ Готово | Создание, закрытие, участие, очистка при удалении |
| Message Deduplication | ✅ Готово | По ID и content matching для temp→real |
| Broadcast Optimization | ✅ Готово | Буферизированный канал (1024), timeout 100ms |
| WebSocket | ✅ Готово | Real-time доставка, targeted routing по UserID |
| File Support | ✅ Готово | MIME-type, file names, binary data |
| Chat Disconnect | ✅ Готово | При закрытии чата - автоматическое отключение собеседника |
| Optimistic UI | ✅ Готово | Temp messages с pending статусом, real ID подтверждение |
| Server Authority | ✅ Готово | Сервер как источник истины, очистка при пустом чате |
| React UI | ✅ Готово | Регистрация, чаты, контакты, сообщения, IndexedDB кеш |
| Docker | ✅ Готово | Контейнеризация сервера и БД |
| Message Broker | ⏳ Планируется | Kafka/RabbitMQ интеграция (опционально) |

---

**Последнее обновление**: 19 декабря 2025

Для вопросов и проблем откройте issue в репозитории!
