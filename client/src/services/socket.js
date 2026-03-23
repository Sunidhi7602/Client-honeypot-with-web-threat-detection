import { io } from 'socket.io-client';

let socket = null;
let listenersBound = false;

const resolveSocketUrl = () => import.meta.env.VITE_SOCKET_URL || window.location.origin;

const bindDebugListeners = (instance) => {
  if (listenersBound) return;

  listenersBound = true;
};

export const getSocket = () => {
  if (!socket) {
    socket = io(resolveSocketUrl(), {
      path: '/socket.io',
      autoConnect: false,
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 10,
      transports: ['websocket', 'polling'],
    });

    bindDebugListeners(socket);
  }

  if (!socket.connected && !socket.active) {
    socket.connect();
  }

  return socket;
};

export const subscribeScan = (scanId) => {
  const instance = getSocket();
  instance.emit('subscribe', { scanId });
};

export const unsubscribeScan = (scanId) => {
  if (!socket) return;
  socket.emit('unsubscribe', { scanId });
};

export const disconnectSocket = () => {
  if (!socket) return;

  socket.disconnect();
  socket = null;
  listenersBound = false;
};
