const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const adapter = new JSONFile('scans.json');
const db = new Low(adapter);
await db.read();
db.data ||= { scans: [] };

const RISK_WEIGHTS = { scriptCount: 0.25, iframeCount: 0.2, redirectCount: 0.15, networkRequests: 0.1 };

function getRiskLevel(score) {
  if (score < 30) return 'Safe';
  if (score < 60) return 'Medium';
  if (score < 80) return 'High';
  return 'Critical';
}

async function runScan(url, scanId) {
  try {
    const browser = await puppeteer.launch({headless: 'new'});
    const page = await browser.newPage();

    let signals = {scriptCount: 0, iframeCount: 0, redirectCount: 0, networkRequests: [], domains: new Set()};

    page.on('request', req => {
      signals.networkRequests.push(req.url());
      try {
        signals.domains.add(new URL(req.url()).hostname);
      } catch {}
    });

    await page.goto(url, {waitUntil: 'networkidle0', timeout: 15000});

    signals.scriptCount = await page.$$eval('script', els => els.length);
    signals.iframeCount = await page.$$eval('iframe', els => els.length);

    const score = Math.min(100, signals.scriptCount * RISK_WEIGHTS.scriptCount * 10 + 
      signals.iframeCount * RISK_WEIGHTS.iframeCount * 20 + 
      signals.networkRequests.length * RISK_WEIGHTS.networkRequests + 10);

    const scan = {
      id: scanId,
      url,
      status: 'complete',
      threatScore: Math.round(score),
      riskLevel: getRiskLevel(score),
      signals,
      iocs: Array.from(signals.domains).map(d => ({type: 'domain', value: d, confidence: 50})),
      submittedAt: new Date().toISOString()
    };

    db.data.scans.unshift(scan);
    await db.write();
    io.emit('scan:complete', scan);
    await browser.close();
  } catch (e) {
    io.emit('scan:error', {id: scanId, error: e.message});
  }
}

app.post('/api/scan', async (req, res) => {
  const {url} = req.body;
  if (!url.startsWith('http')) return res.status(400).json({error: 'Valid URL'});
  const scanId = Date.now().toString();
  runScan(url, scanId);
  res.json({scanId, status: 'queued'});
});

app.get('/api/scans', (req, res) => res.json({scans: db.data.scans.slice(0, 50)}));
app.get('/api/stats', (req, res) => {
  const scans = db.data.scans;
  res.json({
    total: scans.length,
    critical: scans.filter(s => s.riskLevel === 'Critical').length,
    avgScore: scans.reduce((a, s) => a + (s.threatScore||0), 0) / scans.length || 0
  });
});

io.on('connection', socket => {
  socket.on('scan', data => runScan(data.url, Date.now().toString()));
});

server.listen(3000, () => console.log('🍯 HoneyScan v2: http://localhost:3000 - Ready!'));

