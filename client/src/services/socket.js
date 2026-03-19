import { io } from 'socket.io-client';

let socket = null;

export const getSocket = () => {
  if (socket?.connected) return socket;

  socket = io('/', {
    autoConnect: true,
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionAttempts: 10,
    transports: ['websocket', 'polling'],
  });

  socket.on('connect', () => {
    console.log('[Socket.IO] Connected:', socket.id);
  });

  socket.on('disconnect', (reason) => {
    console.warn('[Socket.IO] Disconnected:', reason);
  });

  socket.on('connect_error', (err) => {
    console.error('[Socket.IO] Connection error:', err.message);
  });

  return socket;
};

export const subscribeScan = (scanId) => {
  const s = getSocket();
  s.emit('subscribe', { scanId });
};

export const unsubscribeScan = (scanId) => {
  const s = getSocket();
  s.emit('unsubscribe', { scanId });
};

export const disconnectSocket = () => {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
};
