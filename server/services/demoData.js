const mongoose = require('mongoose');
const Scan = require('../models/Scan');

const DEFAULT_MONGO_URI = 'mongodb://honeyscan:honeyscan_secret@localhost:27017/honeyscan?authSource=admin';

const sampleIOCs = [
  { type: 'domain', value: 'malicious-phish.com', confidence: 95 },
  { type: 'ip', value: '45.76.123.45', confidence: 88 },
  { type: 'url', value: 'http://suspicious-login.net/payload', confidence: 92 },
  { type: 'hash', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', confidence: 100 },
  { type: 'email', value: 'admin@fakebank.com', confidence: 75 },
  { type: 'domain', value: 'exploitkit.cc', confidence: 98 },
  { type: 'url', value: 'https://malware-dropper.net/js/evil.js', confidence: 90 },
  { type: 'ip', value: '198.51.100.42', confidence: 82 },
  { type: 'redirect_chain', value: 'legit.com -> redirector.net -> payload.exe', confidence: 85 },
];

const buildDemoScans = (count = 60) => {
  const scans = [];
  const riskLevels = ['Safe', 'Medium', 'High', 'Critical'];
  const now = new Date();

  for (let i = 0; i < count; i += 1) {
    const daysAgo = Math.floor(Math.random() * 30);
    const hoursAgo = Math.floor(Math.random() * 24);
    const submittedAt = new Date(now - (daysAgo * 86400000 + hoursAgo * 3600000));

    const threatScore = Math.floor(Math.random() * 95) + 5;
    const riskLevel = riskLevels[Math.min(Math.floor(threatScore / 25), riskLevels.length - 1)];

    const isMalicious = Math.random() > 0.4;
    const iocCount = isMalicious ? Math.floor(Math.random() * 4) + 1 : Math.floor(Math.random() * 2);

    scans.push({
      url: isMalicious
        ? `https://malicious-site-${i + 1}.onion/phishing${Math.random() > 0.5 ? '/exploit' : '/malware'}`
        : `https://legit-site-${i + 1}.com/page-${Math.floor(Math.random() * 100)}`,
      status: 'complete',
      scanType: Math.random() > 0.6 ? 'deep' : 'quick',
      submittedAt,
      scanStartedAt: new Date(submittedAt.getTime() + Math.random() * 5000 + 2000),
      completedAt: new Date(submittedAt.getTime() + (Math.random() * 45000 + 15000)),
      threatScore,
      riskLevel,
      recommendedAction: `Review ${riskLevel === 'Critical' ? 'immediately' : 'routine'}`,
      permalink: `/analysis/${new mongoose.Types.ObjectId()}`,
      iocs: Array.from({ length: iocCount }, () => sampleIOCs[Math.floor(Math.random() * sampleIOCs.length)]),
      signals: {
        scriptCount: Math.floor(Math.random() * (isMalicious ? 45 : 10)),
        redirectCount: Math.floor(Math.random() * (isMalicious ? 8 : 2)),
        hiddenIframes: Math.floor(Math.random() * (isMalicious ? 5 : 1)),
        downloadAttempts: Math.floor(Math.random() * (isMalicious ? 3 : 1)),
        externalScripts: Math.floor(Math.random() * (isMalicious ? 25 : 5)),
        domMutationRate: Number((Math.random() * (isMalicious ? 0.8 : 0.2)).toFixed(3)),
      },
      networkCapture: {
        totalPackets: Math.floor(Math.random() * (isMalicious ? 1200 : 300)) + 100,
        suspiciousPackets: threatScore > 40 ? Math.floor(Math.random() * 120) + 20 : Math.floor(Math.random() * 10),
        protocolBreakdown: isMalicious ? { http: 45, https: 30, other: 25 } : { http: 60, https: 35, other: 5 },
        topTalkers: isMalicious
          ? [
              { ip: '198.51.100.178', packets: Math.floor(Math.random() * 400) + 100 },
              { ip: '2001:db8::1', packets: Math.floor(Math.random() * 200) + 50 },
            ]
          : [],
      },
      scoreBreakdown: [],
      normalizedSignals: {},
    });
  }

  return scans;
};

const getDemoConnection = async () => {
  const mongoUri = process.env.MONGO_URI || DEFAULT_MONGO_URI;
  return mongoose.createConnection(mongoUri, {
    serverSelectionTimeoutMS: 10000,
  }).asPromise();
};

const seedDemoData = async ({ clearExisting = true, count = 60, connection = null } = {}) => {
  let conn = connection;
  let ownsConnection = false;

  try {
    if (!conn) {
      conn = await getDemoConnection();
      ownsConnection = true;
    }

    const SeederScan = conn.model('Scan', Scan.schema);

    if (clearExisting) {
      await SeederScan.deleteMany({});
      console.log('[Demo Seed] Cleared existing scans');
    }

    const scans = buildDemoScans(count);
    await SeederScan.insertMany(scans);
    console.log(`[Demo Seed] Inserted ${scans.length} generated demo scans`);

    return { insertedCount: scans.length };
  } finally {
    if (ownsConnection && conn) {
      await conn.close();
      console.log('[Demo Seed] Database connection closed');
    }
  }
};

module.exports = {
  DEFAULT_MONGO_URI,
  buildDemoScans,
  getDemoConnection,
  seedDemoData,
};

if (require.main === module) {
  seedDemoData().catch((error) => {
    console.error('[Demo Seed] Failed:', error.message);
    process.exit(1);
  });
}
