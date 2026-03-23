const express = require('express');
const { Server } = require('socket.io');
const http = require('http');
const cors = require('cors');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const puppeteer = require('puppeteer');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const adapter = new JSONFile('scans.json');
const db = new Low(adapter);
await db.read();
db.data ||= { scans: [] };

// API Routes
app.post('/api/scans', async (req, res) => {
  const scan = {
    id: Date.now().toString(),
    ...req.body,
    status: 'complete',
    threatScore: Math.floor(Math.random() * 100),
    riskLevel: ['Safe', 'Medium', 'High', 'Critical'][Math.floor(Math.random() * 4)],
    signals: { scriptCount: Math.floor(Math.random()*50), redirectCount: Math.floor(Math.random()*5) },
    iocs: [{type: 'domain', value: new URL(req.body.url).hostname, confidence: 75}],
    submittedAt: new Date().toISOString(),
  };
  db.data.scans.unshift(scan);
  await db.write();
  res.json({ scan });
});

app.get('/api/scans', (req, res) => res.json({ scans: db.data.scans.slice(0, 20) }));
app.get('/api/stats/overview', (req, res) => res.json({
  totalScans: db.data.scans.length,
  criticalThreats: db.data.scans.filter(s => s.riskLevel === 'Critical').length,
  avgThreatScore: Math.floor(db.data.scans.reduce((a, s) => a + s.threatScore, 0) / db.data.scans.length || 0),
}));

io.on('connection', (socket) => {
  socket.on('subscribe', ({ scanId }) => socket.join(scanId));
  // Fake scan events
  setInterval(() => {
    socket.emit('scan:progress', { level: 'info', message: 'Fake progress' });
  }, 2000);
});

server.listen(3000, () => console.log('HoneyScan Fresh: http://localhost:3000'));

