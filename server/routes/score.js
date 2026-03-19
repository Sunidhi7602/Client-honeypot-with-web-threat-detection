const express = require('express');
const { authMiddleware } = require('../middleware/auth');
const { computeRiskScore } = require('../services/riskScoringService');

const router = express.Router();

// POST /api/score — Stateless risk scoring
router.post('/', authMiddleware, async (req, res, next) => {
  try {
    const { signals, weights } = req.body;

    if (!signals || typeof signals !== 'object') {
      return res.status(400).json({ error: 'signals object required' });
    }

    // Use user-configured weights or defaults
    const userWeights = req.user?.settings?.riskWeights;
    const result = computeRiskScore(signals, weights || userWeights);

    res.json(result);
  } catch (error) {
    next(error);
  }
});

module.exports = router;
