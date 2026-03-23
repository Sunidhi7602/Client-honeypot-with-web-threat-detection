/**
 * HoneyScan Risk Scoring Service
 * Stateless weighted linear model: ThreatScore = sum(w_i * I_i) * 100
 */

const DEFAULT_WEIGHTS = {
  scriptCount: 0.25,
  redirectCount: 0.20,
  hiddenIframes: 0.20,
  downloadAttempts: 0.15,
  domMutationRate: 0.10,
  externalScripts: 0.10,
};

const NORMALIZATION_CAPS = {
  scriptCount: 50,
  redirectCount: 5,
  hiddenIframes: 3,
  downloadAttempts: 2,
  domMutationRate: 1.0,
  externalScripts: 20,
};

const RISK_LEVELS = [
  { max: 25, level: 'Safe', action: 'No immediate action required. Continue monitoring per standard protocol.' },
  { max: 50, level: 'Medium', action: 'Review behavioral signals manually. Consider blocking domain if patterns persist.' },
  { max: 75, level: 'High', action: 'Block domain at perimeter. Escalate to Tier-2 analyst for full investigation.' },
  { max: 100, level: 'Critical', action: 'IMMEDIATE ACTION: Isolate affected systems, block all traffic, initiate incident response.' },
];

const normalizeSignal = (signal, rawValue) => {
  const cap = NORMALIZATION_CAPS[signal];
  if (!cap) return Math.min(rawValue, 1);
  return Math.min(rawValue / cap, 1);
};

const computeRiskScore = (signals, customWeights = null) => {
  const weights = { ...DEFAULT_WEIGHTS, ...(customWeights || {}) };
  const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0);

  const breakdown = [];
  let rawScore = 0;

  for (const [signal, weight] of Object.entries(weights)) {
    if (!(signal in NORMALIZATION_CAPS)) continue;

    const rawValue = signals[signal] || 0;
    const normalized = normalizeSignal(signal, rawValue);
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
  const riskEntry = RISK_LEVELS.find((entry) => threatScore <= entry.max) || RISK_LEVELS[RISK_LEVELS.length - 1];

  const normalizedSignals = {};
  breakdown.forEach((item) => {
    normalizedSignals[item.signal] = item.normalized;
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

const extractIoCs = (networkRequests = [], redirectChain = [], signals = {}) => {
  const iocs = [];
  const seen = new Set();

  const pushIoc = (ioc) => {
    const type = typeof ioc?.type === 'string' ? ioc.type : '';
    const value = typeof ioc?.value === 'string' ? ioc.value.trim() : '';

    if (!type || !value) return;

    iocs.push({
      ...ioc,
      type,
      value,
      confidence: Number.isFinite(ioc.confidence) ? ioc.confidence : 0,
      firstSeen: ioc.firstSeen || new Date(),
    });
  };

  networkRequests.forEach((req) => {
    try {
      const parsed = new URL(req.url);
      const domain = parsed.hostname;
      const key = `domain:${domain}`;

      if (!seen.has(key)) {
        seen.add(key);
        pushIoc({
          type: 'domain',
          value: domain,
          confidence: req.flagged ? 75 : 30,
          firstSeen: req.timestamp || new Date(),
        });
      }

      const urlKey = `url:${req.url}`;
      if (req.flagged && !seen.has(urlKey)) {
        seen.add(urlKey);
        pushIoc({
          type: 'url',
          value: req.url,
          confidence: 80,
          firstSeen: req.timestamp || new Date(),
        });
      }
    } catch (_) {}
  });

  redirectChain.forEach((hop) => {
    try {
      if (!hop?.to) return;

      const parsed = new URL(hop.to);
      const key = `domain:${parsed.hostname}`;

      if (!seen.has(key)) {
        seen.add(key);
        pushIoc({
          type: 'domain',
          value: parsed.hostname,
          confidence: hop.reputation === 'malicious' ? 90 : hop.reputation === 'suspicious' ? 60 : 25,
          firstSeen: new Date(),
        });
      }
    } catch (_) {}
  });

  if (redirectChain.length > 3) {
    const chainValue = redirectChain
      .map((hop) => hop?.to || hop?.from)
      .filter((value) => typeof value === 'string' && value.trim())
      .join(' -> ');

    pushIoc({
      type: 'redirect_chain',
      value: chainValue.substring(0, 500),
      confidence: Math.min(redirectChain.length * 15, 95),
      firstSeen: new Date(),
    });
  }

  return iocs;
};

module.exports = { computeRiskScore, extractIoCs, DEFAULT_WEIGHTS, NORMALIZATION_CAPS };
