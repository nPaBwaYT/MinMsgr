import Dexie, { Table } from 'dexie';

export interface User {
  id?: number;
  username: string;
  password: string;
  token?: string;
}

export interface Contact {
  id?: number;
  userId: number;
  contactId: number;
  status: 'pending' | 'accepted' | 'blocked';
  createdAt: Date;
}

export interface Chat {
  id: number;
  user1Id: number;
  user2Id: number;
  algorithm: string;
  mode: string;
  padding: string;
  createdAt: Date;
  sessionKey?: string;
  iv?: string;
}

export interface Message {
  id?: number;
  chatId: number;
  senderId: number;
  ciphertext: string;
  iv: string;
  timestamp: Date;
  decrypted?: string;
  type?: 'text' | 'file' | 'image';
  fileName?: string;
}

export class MinMessengerDB extends Dexie {
  users!: Table<User>;
  contacts!: Table<Contact>;
  chats!: Table<Chat>;
  messages!: Table<Message>;

  constructor() {
    super('MinMessengerDB');
    this.version(1).stores({
      users: 'id, username',           // Changed from ++id to id (server provides ID)
      contacts: 'id, userId, contactId, status',  // Changed from ++id to id
      chats: 'id, user1Id, user2Id',   // Changed from ++id to id
      messages: 'id, chatId, senderId, timestamp', // Changed from ++id to id
    });
  }
}

export const db = new MinMessengerDB();
