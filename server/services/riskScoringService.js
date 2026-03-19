/**
 * HoneyScan Risk Scoring Service
 * Stateless weighted linear model: ThreatScore = Σ(wᵢ × Iᵢ) × 100
 */

const DEFAULT_WEIGHTS = {
  scriptCount: 0.25,
  redirectCount: 0.20,
  hiddenIframes: 0.20,
  downloadAttempts: 0.15,
  domMutationRate: 0.10,
  externalScripts: 0.10,
};

// Normalization caps (signals normalized to [0,1])
const NORMALIZATION_CAPS = {
  scriptCount: 50,
  redirectCount: 5,
  hiddenIframes: 3,
  downloadAttempts: 2,
  domMutationRate: 1.0, // already [0,1]
  externalScripts: 20,
};

const RISK_LEVELS = [
  { max: 25, level: 'Safe', action: 'No immediate action required. Continue monitoring per standard protocol.' },
  { max: 50, level: 'Medium', action: 'Review behavioral signals manually. Consider blocking domain if patterns persist.' },
  { max: 75, level: 'High', action: 'Block domain at perimeter. Escalate to Tier-2 analyst for full investigation.' },
  { max: 100, level: 'Critical', action: 'IMMEDIATE ACTION: Isolate affected systems, block all traffic, initiate incident response.' },
];

/**
 * Normalize a raw signal value to [0,1]
 */
const normalizeSignal = (signal, rawValue) => {
  const cap = NORMALIZATION_CAPS[signal];
  if (!cap) return Math.min(rawValue, 1);
  return Math.min(rawValue / cap, 1);
};

/**
 * Compute risk score from raw signals
 * @param {Object} signals - Raw signal counts from Puppeteer
 * @param {Object} customWeights - Optional user-configured weights
 * @returns {Object} Full scoring breakdown
 */
const computeRiskScore = (signals, customWeights = null) => {
  const weights = { ...DEFAULT_WEIGHTS, ...(customWeights || {}) };

  // Ensure weights sum close to 1.0
  const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0);

  const breakdown = [];
  let rawScore = 0;

  for (const [signal, weight] of Object.entries(weights)) {
    if (!(signal in NORMALIZATION_CAPS)) continue;

    const rawValue = signals[signal] || 0;
    const normalized = normalizeSignal(signal, rawValue);
    // Normalize weight to actual proportion
    const normalizedWeight = weight / totalWeight;
    const contribution = normalizedWeight * normalized;

    breakdown.push({
      signal,
      rawValue,
      normalized: parseFloat(normalized.toFixed(4)),
      weight: parseFloat(normalizedWeight.toFixed(4)),
      contribution: parseFloat(contribution.toFixed(4)),
    });

    rawScore += contribution;
  }

  const threatScore = Math.min(Math.round(rawScore * 100), 100);

  const riskEntry = RISK_LEVELS.find(r => threatScore <= r.max) || RISK_LEVELS[RISK_LEVELS.length - 1];

  const normalizedSignals = {};
  breakdown.forEach(b => {
    normalizedSignals[b.signal] = b.normalized;
  });

  return {
    threatScore,
    riskLevel: riskEntry.level,
    recommendedAction: riskEntry.action,
    scoreBreakdown: breakdown,
    normalizedSignals,
    weightsUsed: weights,
    rawScore: parseFloat(rawScore.toFixed(6)),
  };
};

/**
 * Extract IoCs from scan data
 */
const extractIoCs = (networkRequests = [], redirectChain = [], signals = {}) => {
  const iocs = [];
  const seen = new Set();

  // Extract domains from network requests
  networkRequests.forEach(req => {
    try {
      const parsed = new URL(req.url);
      const domain = parsed.hostname;
      const key = `domain:${domain}`;
      if (!seen.has(key)) {
        seen.add(key);
        const isFlagged = req.flagged || false;
        iocs.push({
          type: 'domain',
          value: domain,
          confidence: isFlagged ? 75 : 30,
          firstSeen: req.timestamp || new Date(),
        });
      }

      // Flag suspicious URLs
      const urlKey = `url:${req.url}`;
      if (req.flagged && !seen.has(urlKey)) {
        seen.add(urlKey);
        iocs.push({
          type: 'url',
          value: req.url,
          confidence: 80,
          firstSeen: req.timestamp || new Date(),
        });
      }
    } catch (_) {}
  });

  // Extract redirect chain domains
  redirectChain.forEach(hop => {
    try {
      if (hop.to) {
        const parsed = new URL(hop.to);
        const key = `domain:${parsed.hostname}`;
        if (!seen.has(key)) {
          seen.add(key);
          iocs.push({
            type: 'domain',
            value: parsed.hostname,
            confidence: hop.reputation === 'malicious' ? 90 : hop.reputation === 'suspicious' ? 60 : 25,
            firstSeen: new Date(),
          });
        }
      }
    } catch (_) {}
  });

  // Add redirect chain as IoC if long
  if (redirectChain.length > 3) {
    const chainValue = redirectChain.map(h => h.to || h.from).filter(Boolean).join(' → ');
    iocs.push({
      type: 'redirect_chain',
      value: chainValue.substring(0, 500),
      confidence: Math.min(redirectChain.length * 15, 95),
      firstSeen: new Date(),
    });
  }

  return iocs;
};

module.exports = { computeRiskScore, extractIoCs, DEFAULT_WEIGHTS, NORMALIZATION_CAPS };
