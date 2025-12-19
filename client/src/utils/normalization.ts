// Data normalization utilities for consistent data handling

export interface Contact {
  id: number;
  user1_id: number;
  user2_id: number;
  requester_id?: number;
  username?: string;
  status: string;
  created_at: number;
}

/**
 * Normalize contact data from API response
 */
export function normalizeContact(data: any): Contact {
  return {
    id: data.id,
    user1_id: data.user1_id,
    user2_id: data.user2_id,
    requester_id: data.requester_id,
    username: data.username,
    status: data.status,
    created_at: data.created_at,
  };
}

/**
 * Normalize array of contacts
 */
export function normalizeContacts(data: any[]): Contact[] {
  return data.map(normalizeContact);
}

/**
 * Determine if a contact request is incoming or outgoing for a user
 * @param contact Contact object with requester_id
 * @param userId Current user ID
 * @returns 'incoming' | 'outgoing'
 */
export function getRequestDirection(contact: Contact, userId: number): 'incoming' | 'outgoing' {
  return contact.requester_id === userId ? 'outgoing' : 'incoming';
}

/**
 * Get the other user in a contact relationship
 */
export function getOtherContactUserId(contact: Contact, userId: number): number {
  return contact.user1_id === userId ? contact.user2_id : contact.user1_id;
}
