require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const connectDB = require('./config/db');

const scanRoutes = require('./routes/scans');
const scoreRoutes = require('./routes/score');
const iocRoutes = require('./routes/iocs');
const statsRoutes = require('./routes/stats');

const app = express();
const server = http.createServer(app);

// Socket.IO setup
const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// Attach io instance globally for services
app.set('io', io);
global.io = io;

// Connect to MongoDB
connectDB();

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('combined'));

// Read-heavy dashboards poll several endpoints, so keep the general API limiter
// reasonably high and reserve strict throttling for scan submissions only.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'development' ? 1000 : 600,
  message: { error: 'Too many requests, please try again later.' },
});
app.use('/api/', apiLimiter);

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Scan rate limit exceeded. Max 5 scans per minute.' },
});

app.use('/api/scans', (req, res, next) => {
  if (req.method === 'POST' && req.path === '/') {
    return scanLimiter(req, res, next);
  }
  return next();
});

// Static file serving for pcap downloads
app.use('/captures', express.static(require('path').join(__dirname, 'captures')));

// Routes

app.use('/api/scans', scanRoutes);
app.use('/api/score', scoreRoutes);
app.use('/api/iocs', iocRoutes);
app.use('/api/stats', statsRoutes);
app.use('/api/settings', require('./routes/settings'));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log(`[Socket.IO] Client connected: ${socket.id}`);

  socket.on('subscribe', ({ scanId }) => {
    if (scanId) {
      socket.join(`scan:${scanId}`);
      console.log(`[Socket.IO] ${socket.id} subscribed to scan:${scanId}`);
    }
  });

  socket.on('unsubscribe', ({ scanId }) => {
    if (scanId) {
      socket.leave(`scan:${scanId}`);
      console.log(`[Socket.IO] ${socket.id} unsubscribed from scan:${scanId}`);
    }
  });

  socket.on('disconnect', () => {
    console.log(`[Socket.IO] Client disconnected: ${socket.id}`);
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[Error]', err.stack);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`\n🍯 HoneyScan Server running on port ${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   MongoDB: connecting...`);
  console.log(`   Redis: connecting...`);
  console.log(`   Socket.IO: ready\n`);
});

module.exports = { app, server, io };
