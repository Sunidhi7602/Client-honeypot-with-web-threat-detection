const mongoose = require('mongoose');

// IoC sub-document
const IoCSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['domain', 'ip', 'hash', 'url', 'redirect_chain', 'email', 'registry'],
    required: true,
  },
  value: { type: String, required: true },
  confidence: { type: Number, min: 0, max: 100, default: 0 },
  firstSeen: { type: Date, default: Date.now },
  virusTotalResult: {
    positives: Number,
    total: Number,
    scanDate: String,
    permalink: String,
    cached: { type: Boolean, default: false },
  },
}, { _id: true });

// Score breakdown sub-document
const ScoreBreakdownSchema = new mongoose.Schema({
  signal: String,
  rawValue: Number,
  normalized: Number,
  weight: Number,
  contribution: Number,
}, { _id: false });

// Redirect chain entry
const RedirectNodeSchema = new mongoose.Schema({
  from: String,
  to: String,
  status: Number,
  reputation: { type: String, enum: ['safe', 'suspicious', 'malicious', 'unknown'], default: 'unknown' },
  timestamp: { type: Date, default: Date.now },
}, { _id: false });

// Suricata alert
const SuricataAlertSchema = new mongoose.Schema({
  signature: String,
  severity: { type: Number, min: 1, max: 3 },
  category: String,
  srcIp: String,
  destIp: String,
  srcPort: Number,
  destPort: Number,
  protocol: String,
  timestamp: Date,
  flowId: String,
}, { _id: false });

// Network request log
const NetworkRequestSchema = new mongoose.Schema({
  method: String,
  url: String,
  status: Number,
  size: Number,
  type: String,
  flagged: { type: Boolean, default: false },
  flagReason: String,
  timestamp: { type: Date, default: Date.now },
}, { _id: false });

// Sandbox log entry
const SandboxLogSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  level: { type: String, enum: ['info', 'warn', 'error', 'debug', 'alert'], default: 'info' },
  message: String,
  data: mongoose.Schema.Types.Mixed,
}, { _id: false });

// Main Scan schema
const ScanSchema = new mongoose.Schema({
  url: { type: String, required: true, trim: true },
  submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: {
    type: String,
    enum: ['queued', 'scanning', 'complete', 'error'],
    default: 'queued',
    index: true,
  },
  scanType: {
    type: String,
    enum: ['quick', 'deep'],
    default: 'quick',
  },
  options: {
    redirectDepth: { type: Number, default: 5 },
    observationWindow: { type: Number, default: 30 }, // seconds
    userAgent: { type: String, default: 'HoneyScan/1.0 (Research Scanner)' },
    enableSuricata: { type: Boolean, default: false },
    enableWireshark: { type: Boolean, default: false },
  },

  // Timing
  submittedAt: { type: Date, default: Date.now, index: true },
  scanStartedAt: Date,
  completedAt: Date,

  // Raw signal counts from Puppeteer/CDP
  signals: {
    scriptCount: { type: Number, default: 0 },
    redirectCount: { type: Number, default: 0 },
    hiddenIframes: { type: Number, default: 0 },
    downloadAttempts: { type: Number, default: 0 },
    domMutationRate: { type: Number, default: 0 },
    externalScripts: { type: Number, default: 0 },
    consoleErrors: { type: Number, default: 0 },
    cookiesSet: { type: Number, default: 0 },
    localStorageWrites: { type: Number, default: 0 },
  },

  // Normalized [0,1]
  normalizedSignals: {
    scriptCount: Number,
    redirectCount: Number,
    hiddenIframes: Number,
    downloadAttempts: Number,
    domMutationRate: Number,
    externalScripts: Number,
  },

  // Per-signal breakdown
  scoreBreakdown: [ScoreBreakdownSchema],

  // Final score
  threatScore: { type: Number, min: 0, max: 100, index: true },
  riskLevel: {
    type: String,
    enum: ['Safe', 'Medium', 'High', 'Critical'],
    index: true,
  },
  recommendedAction: String,

  // IoCs
  iocs: [IoCSchema],

  // Network capture (Wireshark/tshark)
  networkCapture: {
    totalPackets: { type: Number, default: 0 },
    suspiciousPackets: { type: Number, default: 0 },
    pcapPath: String,
    protocolBreakdown: {
      http: { type: Number, default: 0 },
      https: { type: Number, default: 0 },
      dns: { type: Number, default: 0 },
      other: { type: Number, default: 0 },
    },
    suricataAlerts: [SuricataAlertSchema],
    topTalkers: [{ ip: String, packets: Number }],
  },

  // Sandbox execution log
  sandboxLog: [SandboxLogSchema],

  // Live network requests captured by CDP
  networkRequests: [NetworkRequestSchema],

  // Redirect chain
  redirectChain: [RedirectNodeSchema],

  // DOM snapshots (stored as strings)
  domSnapshotBefore: { type: String, select: false },
  domSnapshotAfter: { type: String, select: false },

  // Error info
  errorMessage: String,
  errorStack: { type: String, select: false },

}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

// Indexes for dashboard queries
ScanSchema.index({ submittedAt: -1 });
ScanSchema.index({ riskLevel: 1, submittedAt: -1 });
ScanSchema.index({ threatScore: -1 });

// Virtual: scan duration in seconds
ScanSchema.virtual('duration').get(function () {
  if (this.scanStartedAt && this.completedAt) {
    return Math.round((this.completedAt - this.scanStartedAt) / 1000);
  }
  return null;
});

// Static: get severity counts for donut chart
ScanSchema.statics.getSeverityDistribution = async function () {
  return this.aggregate([
    { $match: { status: 'complete' } },
    { $group: { _id: '$riskLevel', count: { $sum: 1 } } },
    { $sort: { _id: 1 } },
  ]);
};

// Static: scans per day for area chart
ScanSchema.statics.getScansPerDay = async function (days = 30) {
  const since = new Date();
  since.setDate(since.getDate() - days);
  return this.aggregate([
    { $match: { submittedAt: { $gte: since }, status: 'complete' } },
    {
      $group: {
        _id: { $dateToString: { format: '%Y-%m-%d', date: '$submittedAt' } },
        total: { $sum: 1 },
        highCritical: {
          $sum: {
            $cond: [{ $in: ['$riskLevel', ['High', 'Critical']] }, 1, 0],
          },
        },
        avgScore: { $avg: '$threatScore' },
      },
    },
    { $sort: { _id: 1 } },
  ]);
};

// Static: heatmap data (7x24 grid)
ScanSchema.statics.getHeatmapData = async function () {
  const since = new Date();
  since.setDate(since.getDate() - 7);
  return this.aggregate([
    { $match: { submittedAt: { $gte: since }, status: 'complete' } },
    {
      $group: {
        _id: {
          dayOfWeek: { $dayOfWeek: '$submittedAt' },
          hour: { $hour: '$submittedAt' },
        },
        avgScore: { $avg: '$threatScore' },
        count: { $sum: 1 },
      },
    },
  ]);
};

module.exports = mongoose.model('Scan', ScanSchema);
