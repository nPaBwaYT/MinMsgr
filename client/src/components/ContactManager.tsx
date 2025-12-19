import React, { useState, useEffect } from 'react';
import apiService, { wsService } from '../api';
import { db, Contact } from '../db';

interface ContactListProps {
  userId: number;
  onSelectContact?: (contactId: number) => void;
}

export const ContactManager: React.FC<ContactListProps> = ({ userId }) => {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [pendingRequests, setPendingRequests] = useState<any[]>([]);
  const [newContactId, setNewContactId] = useState('');
  const [loading, setLoading] = useState(false);
  const [contactsError, setContactsError] = useState('');
  const [pendingError, setPendingError] = useState('');

  useEffect(() => {
    // Clear errors on mount before loading
    setContactsError('');
    setPendingError('');
    loadContacts();
    loadPendingRequests();

    // Subscribe to all events for debugging
    const unsubscribeAll = wsService.subscribe('*', (event: any) => {
      console.log('[ContactManager] Received event:', event.type, event);
      
      // Handle specific contact event types
      if (event.type === 'contact_request') {
        console.log('[ContactManager] New contact request received');
        loadPendingRequests();
        loadContacts();
      } else if (event.type === 'contact_accepted') {
        console.log('[ContactManager] Contact request accepted');
        loadPendingRequests();
        loadContacts();
      } else if (event.type === 'contact_rejected') {
        console.log('[ContactManager] Contact request rejected');
        loadPendingRequests();
        loadContacts();
      } else if (event.type === 'contact_removed') {
        console.log('[ContactManager] Contact removed');
        loadContacts();
        loadPendingRequests();
      } else if (event.type === 'chat_created') {
        console.log('[ContactManager] Chat created');
        loadContacts();
      }
    });

    return () => {
      unsubscribeAll();
    };
  }, [userId]);

  const loadContacts = async () => {
    setContactsError(''); // Clear error before attempting load
    try {
      const response = await apiService.getContacts();
      const contactsList = response.contacts || [];
      
      if (!Array.isArray(contactsList)) {
        throw new Error('Contacts list is not an array');
      }

      const transformedContacts = contactsList.map((c: any) => {
        const id = c.id || c.ID;
        const user1Id = c.user1_id || c.User1ID;
        const user2Id = c.user2_id || c.User2ID;
        const contactId = user1Id === userId ? user2Id : user1Id;
        
        if (!id || !contactId) {
          console.warn('[ContactManager] Skipping malformed contact:', c);
          return null;
        }
        
        return {
          id,
          userId: userId,
          contactId,
          status: c.status || c.Status || 'accepted',
          createdAt: new Date(((c.created_at || c.CreatedAt) ? (c.created_at || c.CreatedAt) * 1000 : Date.now())),
        };
      }).filter((c: any) => c !== null) as Contact[];

      // Save to local DB with error handling for duplicates
      try {
        await db.contacts.clear();
      } catch (err) {
        console.warn('[ContactManager] Error clearing contacts:', err);
      }
      
      try {
        if (transformedContacts.length > 0) {
          // Use bulkPut instead of bulkAdd to overwrite duplicates
          await db.contacts.bulkPut(transformedContacts);
        }
      } catch (err) {
        console.warn('[ContactManager] Bulk put failed, trying individual inserts:', err);
        // Fallback: insert/update individually
        for (const contact of transformedContacts) {
          try {
            await db.contacts.put(contact);
          } catch (e) {
            console.warn('[ContactManager] Failed to save contact', contact.id, e);
          }
        }
      }
      
      setContacts(transformedContacts);
    } catch (err: any) {
      console.error('[ContactManager] Failed to load contacts:', err);
      setContactsError('Failed to load contacts: ' + err.message);
    }
  };

  const loadPendingRequests = async () => {
    setPendingError(''); // Clear error before attempting load
    try {
      const response = await apiService.getPendingRequests();
      const requests = response.requests || [];

      if (!Array.isArray(requests)) {
        throw new Error('Requests list is not an array');
      }

      const transformedRequests = requests.map((c: any) => {
        const id = c.id || c.ID;
        const user1Id = c.user1_id || c.User1ID;
        const user2Id = c.user2_id || c.User2ID;
        const requesterId = c.requester_id || c.RequesterID;
        const contactId = user1Id === userId ? user2Id : user1Id;

        if (!id || !contactId) {
          console.warn('[ContactManager] Skipping malformed pending request:', c);
          return null;
        }

        // The current user is the recipient if they are NOT the requester
        const isRecipient = requesterId !== userId;

        return {
          id,
          userId: userId,
          contactId,
          status: 'pending',
          isRecipient,
          requesterId,
          createdAt: new Date(((c.created_at || c.CreatedAt) ? (c.created_at || c.CreatedAt) * 1000 : Date.now())),
        };
      }).filter((r: any) => r !== null);

      setPendingRequests(transformedRequests);
    } catch (err: any) {
      console.error('Failed to load pending requests', err);
      setPendingError('Failed to load pending requests: ' + err.message);
    }
  };

  const handleAddContact = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newContactId.trim()) return;

    setLoading(true);
    try {
      const contactId = parseInt(newContactId);
      console.log('[ContactManager] Sending contact request to user:', contactId);
      await apiService.sendContactRequest(contactId, 'add');
      console.log('[ContactManager] Contact request sent, clearing input');
      setNewContactId('');
      
      // Wait a bit for server to process and broadcast the event
      console.log('[ContactManager] Waiting for server to process...');
      await new Promise(resolve => setTimeout(resolve, 500));
      
      console.log('[ContactManager] Reloading contacts after add request');
      await loadContacts();
      await loadPendingRequests();
      setContactsError('');
      console.log('[ContactManager] Contacts reloaded after add request');
    } catch (err: any) {
      console.error('[ContactManager] Failed to add contact:', err);
      setContactsError('Failed to add contact: ' + (err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveContact = async (contactId: number) => {
    if (!confirm('Remove this contact?')) return;

    try {
      await apiService.sendContactRequest(contactId, 'remove');
      await loadContacts();
    } catch (err) {
      setContactsError('Failed to remove contact');
    }
  };

  const handleAcceptRequest = async (contactId: number) => {
    setLoading(true);
    try {
      await apiService.acceptContact(contactId);
      setPendingError('');
      await loadPendingRequests();
      await loadContacts();
    } catch (err: any) {
      setPendingError('Failed to accept contact request');
    } finally {
      setLoading(false);
    }
  };

  const handleRejectRequest = async (contactId: number) => {
    if (!confirm('Reject this contact request?')) return;

    setLoading(true);
    try {
      await apiService.rejectContact(contactId);
      setPendingError('');
      await loadPendingRequests();
    } catch (err: any) {
      setPendingError('Failed to reject contact request');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow p-6">
      <h2 className="text-2xl font-bold mb-4 text-gray-800">Contacts</h2>

      <form onSubmit={handleAddContact} className="mb-6 space-y-2">
        <div className="flex gap-2">
          <input
            type="number"
            value={newContactId}
            onChange={(e) => setNewContactId(e.target.value)}
            placeholder="Enter contact user ID"
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
          >
            Add Contact
          </button>
        </div>
      </form>

      {contactsError && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-2 rounded mb-4">
          {contactsError}
        </div>
      )}
      {pendingError && (
        <div className="bg-yellow-100 border border-yellow-400 text-yellow-800 px-4 py-2 rounded mb-4">
          {pendingError}
        </div>
      )}

      {/* Pending Requests Section */}
      {pendingRequests.length > 0 && (
        <div className="mb-6">
          <h3 className="text-lg font-bold mb-2 text-gray-800">Pending Requests</h3>
          <div className="space-y-2 max-h-40 overflow-y-auto">
            {pendingRequests.map((request) => (
              <div
                key={request.id}
                className="flex items-center justify-between p-3 bg-yellow-50 rounded-lg border border-yellow-200"
              >
                <div>
                  <p className="font-medium text-gray-800">User {request.contactId}</p>
                  <p className="text-sm text-gray-500">Contact request</p>
                </div>
                <div className="flex gap-2">
                  {request.isRecipient ? (
                    <>
                      <button
                        onClick={() => handleAcceptRequest(request.contactId)}
                        disabled={loading}
                        className="bg-green-500 hover:bg-green-600 text-white px-3 py-1 rounded text-sm transition disabled:opacity-50"
                      >
                        Accept
                      </button>
                      <button
                        onClick={() => handleRejectRequest(request.contactId)}
                        disabled={loading}
                        className="bg-red-500 hover:bg-red-600 text-white px-3 py-1 rounded text-sm transition disabled:opacity-50"
                      >
                        Reject
                      </button>
                    </>
                  ) : (
                    <span className="text-sm text-gray-600 italic">Pending</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <h3 className="text-lg font-bold mb-2 text-gray-800">Accepted Contacts</h3>
      <div className="space-y-2 max-h-64 overflow-y-auto">
        {contacts.length === 0 ? (
          <p className="text-gray-500 text-center py-4">No contacts yet</p>
        ) : (
          contacts.map((contact) => (
            <div
              key={contact.id}
              className="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition"
            >
              <div>
                <p className="font-medium text-gray-800">User {contact.contactId}</p>
                <p className="text-sm text-gray-500 capitalize">{contact.status}</p>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => handleRemoveContact(contact.contactId)}
                  className="bg-red-500 hover:bg-red-600 text-white px-3 py-1 rounded text-sm"
                >
                  Remove
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
