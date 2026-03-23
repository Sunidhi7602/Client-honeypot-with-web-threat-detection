const express = require('express');
const router = express.Router();

// Stub settings API for Settings page
// GET /api/settings — Current user preferences (demo mode)
router.get('/', (req, res) => {
  res.json({
    theme: 'dark',
    riskWeights: {
      scriptCount: 0.25,
      redirectCount: 0.20,
      hiddenIframes: 0.20,
      downloadAttempts: 0.15,
      domMutationRate: 0.10,
      externalScripts: 0.10,
    },
    scanDefaults: {
      observationWindow: 30,
      redirectDepth: 5,
      enableSuricata: false,
      enableWireshark: true,
    },
    virusTotalEnabled: !!process.env.VIRUSTOTAL_API_KEY,
    notifications: {
      critical: true,
      high: true,
      medium: true,
    },
  });
});

// POST /api/settings — Update preferences (stub - no persistence)
router.post('/', (req, res) => {
  res.json({ message: 'Settings saved successfully' });
});

module.exports = router;

