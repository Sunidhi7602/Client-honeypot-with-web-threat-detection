const express = require('express');
const Scan = require('../models/Scan');


const router = express.Router();

// GET /api/iocs — All IoCs across all scans
router.get('/', async (req, res, next) => {
  try {
    const { type, search, page = 1, limit = 50 } = req.query;
    const matchStage = { status: 'complete' };
    const iocMatch = {};
    if (type) iocMatch['iocs.type'] = type;
    if (search) iocMatch['iocs.value'] = { $regex: search, $options: 'i' };

    const pipeline = [
      { $match: matchStage },
      { $unwind: '$iocs' },
      ...(Object.keys(iocMatch).length > 0 ? [{ $match: iocMatch }] : []),
      { $sort: { 'iocs.firstSeen': -1 } },
      { $skip: (parseInt(page) - 1) * parseInt(limit) },
      { $limit: parseInt(limit) },
      {
        $project: {
          scanId: '$_id',
          url: 1,
          ioc: '$iocs',
          threatScore: 1,
          riskLevel: 1,
        },
      },
    ];

    const iocs = await Scan.aggregate(pipeline);
    res.json({ iocs });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
