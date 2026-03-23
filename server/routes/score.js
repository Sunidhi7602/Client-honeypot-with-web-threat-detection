const express = require('express');

const { computeRiskScore } = require('../services/riskScoringService');

const router = express.Router();

// POST /api/score — Stateless risk scoring
router.post('/', async (req, res, next) => {
  try {
    const { signals, weights } = req.body;

    if (!signals || typeof signals !== 'object') {
      return res.status(400).json({ error: 'signals object required' });
    }

    // Use user-configured weights or defaults
    const userWeights = { scriptCount: 0.25, redirectCount: 0.20, hiddenIframes: 0.20, downloadAttempts: 0.15, domMutationRate: 0.10, externalScripts: 0.10 };
    const result = computeRiskScore(signals, weights || userWeights);

    res.json(result);
  } catch (error) {
    next(error);
  }
});

module.exports = router;
