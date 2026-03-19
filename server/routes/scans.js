const express = require('express');
const { body, validationResult } = require('express-validator');
const { v4: uuidv4 } = require('uuid');
const Scan = require('../models/Scan');
const { authMiddleware } = require('../middleware/auth');
const { addScanJob } = require('../services/scanQueue');
const path = require('path');
const fs = require('fs');

const router = express.Router();

// POST /api/scans — Submit URL for scanning
router.post('/', authMiddleware, [
  body('url').isURL({ require_protocol: true }).withMessage('Valid URL with protocol required'),
  body('scanType').optional().isIn(['quick', 'deep']),
  body('options.redirectDepth').optional().isInt({ min: 1, max: 20 }),
  body('options.observationWindow').optional().isInt({ min: 10, max: 120 }),
], async (req, res, next) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { url, scanType = 'quick', options = {} } = req.body;
    const userDefaults = req.user.settings?.scanDefaults || {};

    const scan = new Scan({
      url,
      submittedBy: req.user._id,
      scanType,
      status: 'queued',
      options: {
        redirectDepth: options.redirectDepth || userDefaults.maxRedirectDepth || 5,
        observationWindow: options.observationWindow || userDefaults.observationWindow || 30,
        userAgent: options.userAgent || userDefaults.userAgent || 'HoneyScan/1.0 (Research Scanner)',
        enableSuricata: options.enableSuricata ?? userDefaults.enableSuricata ?? false,
        enableWireshark: scanType === 'deep',
      },
    });

    await scan.save();

    // Enqueue the scan job
    const jobId = await addScanJob({
      scanId: scan._id.toString(),
      url,
      scanType,
      options: scan.options,
      riskWeights: req.user.settings?.riskWeights,
    });

    res.status(202).json({
      message: 'Scan queued successfully',
      scan: { _id: scan._id, url, status: 'queued', scanType, submittedAt: scan.submittedAt },
      jobId,
    });
  } catch (error) {
    next(error);
  }
});

// GET /api/scans — List scans (paginated)
router.get('/', authMiddleware, async (req, res, next) => {
  try {
    const {
      page = 1,
      limit = 20,
      sortBy = 'submittedAt',
      sortOrder = 'desc',
      search = '',
      riskLevel = '',
      status = '',
    } = req.query;

    const query = {};
    if (search) {
      query.url = { $regex: search, $options: 'i' };
    }
    if (riskLevel) query.riskLevel = riskLevel;
    if (status) query.status = status;

    const sort = { [sortBy]: sortOrder === 'asc' ? 1 : -1 };
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [scans, total] = await Promise.all([
      Scan.find(query)
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .select('-sandboxLog -networkRequests -domSnapshotBefore -domSnapshotAfter -errorStack'),
      Scan.countDocuments(query),
    ]);

    res.json({
      scans,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (error) {
    next(error);
  }
});

// GET /api/scans/recent — Recent scans for live dashboard feed
router.get('/recent', authMiddleware, async (req, res, next) => {
  try {
    const scans = await Scan.find({ status: { $in: ['complete', 'scanning'] } })
      .sort({ submittedAt: -1 })
      .limit(10)
      .select('url status threatScore riskLevel submittedAt completedAt iocs');
    res.json({ scans });
  } catch (error) {
    next(error);
  }
});

// GET /api/scans/:id — Get single scan with full details
router.get('/:id', authMiddleware, async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id)
      .select('-errorStack');

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    res.json({ scan });
  } catch (error) {
    next(error);
  }
});

// GET /api/scans/:id/dom — Get DOM snapshots (heavy, separate endpoint)
router.get('/:id/dom', authMiddleware, async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id)
      .select('domSnapshotBefore domSnapshotAfter url status');
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    res.json({
      before: scan.domSnapshotBefore,
      after: scan.domSnapshotAfter,
    });
  } catch (error) {
    next(error);
  }
});

// DELETE /api/scans/:id
router.delete('/:id', authMiddleware, async (req, res, next) => {
  try {
    const scan = await Scan.findByIdAndDelete(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    // Clean up pcap file
    if (scan.networkCapture?.pcapPath) {
      try { fs.unlinkSync(scan.networkCapture.pcapPath); } catch (_) {}
    }

    res.json({ message: 'Scan deleted successfully' });
  } catch (error) {
    next(error);
  }
});

// POST /api/scans/bulk-delete
router.post('/bulk-delete', authMiddleware, async (req, res, next) => {
  try {
    const { ids } = req.body;
    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'IDs array required' });
    }
    const result = await Scan.deleteMany({ _id: { $in: ids } });
    res.json({ deleted: result.deletedCount });
  } catch (error) {
    next(error);
  }
});

// GET /api/scans/:id/export — Export scan as JSON
router.get('/:id/export', authMiddleware, async (req, res, next) => {
  try {
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="honeyscan-${scan._id}.json"`);
    res.json(scan.toObject());
  } catch (error) {
    next(error);
  }
});

// POST /api/scans/export-csv — Bulk export
router.post('/export-csv', authMiddleware, async (req, res, next) => {
  try {
    const { ids } = req.body;
    const query = ids?.length ? { _id: { $in: ids } } : {};
    const scans = await Scan.find(query).select('url status threatScore riskLevel submittedAt completedAt iocs');

    const header = 'URL,Status,ThreatScore,RiskLevel,SubmittedAt,CompletedAt,IoCCount\n';
    const rows = scans.map(s =>
      `"${s.url}","${s.status}",${s.threatScore || ''},"${s.riskLevel || ''}","${s.submittedAt?.toISOString() || ''}","${s.completedAt?.toISOString() || ''}",${s.iocs?.length || 0}`
    ).join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="honeyscan-export.csv"');
    res.send(header + rows);
  } catch (error) {
    next(error);
  }
});

// POST /api/scans/:id/ioc/:iocId/virustotal — Trigger VT lookup
router.post('/:id/ioc/:iocId/virustotal', authMiddleware, async (req, res, next) => {
  try {
    const { virusTotalLookup } = require('../services/virusTotalService');
    const scan = await Scan.findById(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const ioc = scan.iocs.id(req.params.iocId);
    if (!ioc) return res.status(404).json({ error: 'IoC not found' });

    const apiKey = req.user.settings?.virusTotalApiKey;
    if (!apiKey) {
      return res.status(400).json({ error: 'VirusTotal API key not configured in settings' });
    }

    const result = await virusTotalLookup(ioc.value, ioc.type, apiKey);
    ioc.virusTotalResult = result;
    await scan.save();

    res.json({ ioc });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
