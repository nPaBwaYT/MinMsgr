// Unified WebSocket event subscription hook
import { useEffect } from 'react';
import { wsService } from '../api';

/**
 * Reusable hook for subscribing to WebSocket events
 * @param eventType - Type of event to listen for
 * @param handler - Callback function when event is received
 * @param deps - Dependency array for useEffect
 */
export function useWebSocketEvent(
  eventType: string,
  handler: (event: any) => void,
  deps: any[] = []
) {
  useEffect(() => {
    const unsubscribe = wsService.subscribe(eventType, handler);
    return unsubscribe;
  }, [eventType, handler, ...deps]);
}

/**
 * Hook for multiple event listeners
 * @param events - Map of event type to handler
 * @param deps - Dependency array
 */
export function useWebSocketEvents(
  events: Record<string, (event: any) => void>,
  deps: any[] = []
) {
  useEffect(() => {
    const unsubscribers = Object.entries(events).map(([type, handler]) =>
      wsService.subscribe(type, handler)
    );

    return () => {
      unsubscribers.forEach(unsub => unsub());
    };
  }, [events, ...deps]);
}
