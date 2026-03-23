const express = require('express');
const Scan = require('../models/Scan');


const router = express.Router();

// GET /api/stats/overview — 4 stat cards
router.get('/overview', async (req, res, next) => {
  try {
    const [totalScans, criticalScans, avgScoreResult, totalIoCsResult] = await Promise.all([
      Scan.countDocuments({ status: 'complete' }),
      Scan.countDocuments({ status: 'complete', riskLevel: 'Critical' }),
      Scan.aggregate([
        { $match: { status: 'complete', threatScore: { $exists: true } } },
        { $group: { _id: null, avg: { $avg: '$threatScore' } } },
      ]),
      Scan.aggregate([
        { $match: { status: 'complete' } },
        { $project: { iocCount: { $size: { $ifNull: ['$iocs', []] } } } },
        { $group: { _id: null, total: { $sum: '$iocCount' } } },
      ]),
    ]);

    res.json({
      totalScans,
      criticalThreats: criticalScans,
      avgThreatScore: avgScoreResult[0]?.avg ? Math.round(avgScoreResult[0].avg) : 0,
      iocsDiscovered: totalIoCsResult[0]?.total || 0,
    });
  } catch (error) {
    next(error);
  }
});

// GET /api/stats/scans-per-day
router.get('/scans-per-day', async (req, res, next) => {
  try {
    const days = parseInt(req.query.days) || 30;
    const data = await Scan.getScansPerDay(days);
    res.json({ data });
  } catch (error) {
    next(error);
  }
});

// GET /api/stats/severity-distribution
router.get('/severity-distribution', async (req, res, next) => {
  try {
    const data = await Scan.getSeverityDistribution();
    res.json({ data });
  } catch (error) {
    next(error);
  }
});

// GET /api/stats/heatmap
router.get('/heatmap', async (req, res, next) => {
  try {
    const data = await Scan.getHeatmapData();
    res.json({ data });
  } catch (error) {
    next(error);
  }
});

// GET /api/stats/top-ioc-types
router.get('/top-ioc-types', async (req, res, next) => {
  try {
    const data = await Scan.aggregate([
      { $match: { status: 'complete' } },
      { $unwind: '$iocs' },
      { $group: { _id: '$iocs.type', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]);
    res.json({ data });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
