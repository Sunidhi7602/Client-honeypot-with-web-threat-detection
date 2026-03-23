const mongoose = require('mongoose');
const Scan = require('../models/Scan');
require('dotenv').config({ path: './.env' });

const connectDB = require('../config/db');

const SAMPLE_SCANS = [
  {
    url: 'https://httpbin.org/redirect/5',
    scanType: 'quick',
    status: 'complete',
    threatScore: 87,
    riskLevel: 'Critical',
    signals: {
      scriptCount: 45,
      redirectCount: 5,
      hiddenIframes: 3,
      downloadAttempts: 2,
      externalScripts: 18,
    },
    iocs: [
      { type: 'domain', value: 'httpbin.org', confidence: 75 },
      { type: 'redirect_chain', value: 'httpbin.org → httpbin.org/redirect/1 → ...', confidence: 90 },
    ],
    submittedAt: new Date(Date.now() - 1000*60*60*2),
    completedAt: new Date(Date.now() - 1000*60*60*1.5),
    scoreBreakdown: [
      { signal: 'redirectCount', rawValue: 5, normalized: 1.0, weight: 0.20, contribution: 0.20 },
      { signal: 'hiddenIframes', rawValue: 3, normalized: 1.0, weight: 0.20, contribution: 0.20 },
    ],
    networkCapture: {
      totalPackets: 1250,
      suspiciousPackets: 23,
      protocolBreakdown: { http: 450, https: 200, dns: 300, other: 300 },
    },
  },
  {
    url: 'https://example.com/iframe-test',
    scanType: 'deep',
    status: 'complete',
    threatScore: 42,
    riskLevel: 'Medium',
    signals: { scriptCount: 12, hiddenIframes: 2, externalScripts: 8 },
    iocs: [{ type: 'domain', value: 'example.com', confidence: 45 }],
    submittedAt: new Date(Date.now() - 1000*60*60*6),
  },
  {
    url: 'https://benign-site.com',
    scanType: 'quick',
    status: 'complete',
    threatScore: 12,
    riskLevel: 'Safe',
    signals: { scriptCount: 3 },
    submittedAt: new Date(Date.now() - 1000*60*60*12),
  },
  {
    url: 'https://suspicious-phish.com',
    scanType: 'deep',
    status: 'scanning',
    submittedAt: new Date(Date.now() - 1000*60*30),
  },
  // Add 10+ more for pagination/heatmap/stats...
];

const seedData = async () => {
  await connectDB();
  
  // Clear existing (dev only)
  await Scan.deleteMany({});
  
  // Insert samples
  const scans = await Scan.insertMany(SAMPLE_SCANS);
  
  console.log(`✅ Seeded ${scans.length} sample scans to MongoDB`);
  
  // Verify dashboard stats
  const stats = await Scan.aggregate([
    { $match: { status: 'complete' } },
    { $group: { _id: '$riskLevel', count: { $sum: 1 } } }
  ]);
  console.log('Dashboard stats:', stats);
  
  mongoose.connection.close();
};

seedData().catch(console.error);

