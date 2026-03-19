/**
 * HoneyScan Scan Processor
 * Orchestrates: VM restore → Puppeteer scan → Wireshark → Suricata → Risk scoring → IoC extraction
 */

const Scan = require('../models/Scan');
const { runPuppeteerScan } = require('../sandbox/scan');
const { computeRiskScore, extractIoCs } = require('./riskScoringService');
const { startWiresharkCapture, stopWiresharkCapture } = require('./wiresharkService');
const { getSuricataAlerts } = require('./suricataService');

const emit = (scanId, event, data) => {
  if (global.io) {
    global.io.to(`scan:${scanId}`).emit(event, data);
  }
};

const log = async (scan, level, message, data = null) => {
  const entry = { timestamp: new Date(), level, message, data };
  scan.sandboxLog.push(entry);
  emit(scan._id.toString(), 'scan:progress', { level, message, timestamp: entry.timestamp });
  console.log(`[Scan ${scan._id}] [${level.toUpperCase()}] ${message}`);
};

const SCAN_STEPS = [
  'VM Restore',
  'Browser Navigation',
  'Signal Extraction',
  'Wireshark Capture',
  'Suricata Check',
  'Risk Scoring',
  'IoC Extraction',
];

module.exports = async (job) => {
  const { scanId, url, scanType, options, riskWeights } = job.data;

  const scan = await Scan.findById(scanId);
  if (!scan) throw new Error(`Scan ${scanId} not found in database`);

  scan.status = 'scanning';
  scan.scanStartedAt = new Date();
  await scan.save();

  const scanStartTime = new Date();
  let wiresharkProc = null;

  try {
    // === STEP 1: VM Restore ===
    emit(scanId, 'scan:step', { step: 0, name: SCAN_STEPS[0], status: 'active' });
    await log(scan, 'info', `[VM] Restoring VirtualBox snapshot for clean state...`);
    job.progress(5);

    const { restoreVM } = require('../sandbox/vmManager');
    await restoreVM(options);

    await log(scan, 'info', '[VM] Snapshot restored successfully. Starting browser...');
    emit(scanId, 'scan:step', { step: 0, name: SCAN_STEPS[0], status: 'done' });
    job.progress(15);

    // === STEP 2: Start Wireshark (if deep scan) ===
    if (scanType === 'deep' && options.enableWireshark) {
      emit(scanId, 'scan:step', { step: 3, name: SCAN_STEPS[3], status: 'active' });
      await log(scan, 'info', '[Wireshark] Starting packet capture on vboxnet0...');
      wiresharkProc = await startWiresharkCapture(scanId);
      await log(scan, 'info', `[Wireshark] Capture started → /captures/${scanId}.pcap`);
    }

    // === STEP 3: Browser Navigation & Signal Collection ===
    emit(scanId, 'scan:step', { step: 1, name: SCAN_STEPS[1], status: 'active' });
    await log(scan, 'info', `[Browser] Launching headless Chromium with CDP instrumentation...`);
    await log(scan, 'info', `[Browser] Navigating to: ${url}`);
    job.progress(20);

    const puppeteerResult = await runPuppeteerScan(
      { url, options, scanId },
      // Event callbacks
      {
        onNetworkRequest: (req) => {
          scan.networkRequests.push(req);
          emit(scanId, 'scan:network', req);
        },
        onRedirect: (hop) => {
          scan.redirectChain.push(hop);
          emit(scanId, 'scan:progress', { level: 'info', message: `[Redirect] ${hop.from} → ${hop.to} (${hop.status})` });
        },
        onLog: async (level, message, data) => {
          await log(scan, level, message, data);
        },
      }
    );

    emit(scanId, 'scan:step', { step: 1, name: SCAN_STEPS[1], status: 'done' });
    job.progress(50);

    // === STEP 4: Signal Extraction ===
    emit(scanId, 'scan:step', { step: 2, name: SCAN_STEPS[2], status: 'active' });
    await log(scan, 'info', '[Signals] Extracting behavioral signals from execution trace...');

    scan.signals = puppeteerResult.signals;
    scan.domSnapshotBefore = puppeteerResult.domBefore;
    scan.domSnapshotAfter = puppeteerResult.domAfter;

    await log(scan, 'info', `[Signals] scriptCount=${scan.signals.scriptCount}, redirects=${scan.signals.redirectCount}, hiddenIframes=${scan.signals.hiddenIframes}, downloads=${scan.signals.downloadAttempts}`);
    emit(scanId, 'scan:step', { step: 2, name: SCAN_STEPS[2], status: 'done' });
    job.progress(60);

    // === STEP 5: Stop Wireshark & Parse ===
    if (wiresharkProc) {
      emit(scanId, 'scan:step', { step: 3, name: SCAN_STEPS[3], status: 'active' });
      await log(scan, 'info', '[Wireshark] Stopping capture and parsing packets...');

      const pcapData = await stopWiresharkCapture(wiresharkProc, scanId);
      scan.networkCapture = {
        totalPackets: pcapData.totalPackets,
        suspiciousPackets: pcapData.suspiciousPackets,
        pcapPath: pcapData.pcapPath,
        protocolBreakdown: pcapData.protocolBreakdown,
        topTalkers: pcapData.topTalkers || [],
        suricataAlerts: [],
      };

      await log(scan, 'info', `[Wireshark] Captured ${pcapData.totalPackets} packets. ${pcapData.suspiciousPackets} flagged.`);
      emit(scanId, 'scan:step', { step: 3, name: SCAN_STEPS[3], status: 'done' });
    }

    job.progress(70);

    // === STEP 6: Suricata IDS ===
    if (options.enableSuricata) {
      emit(scanId, 'scan:step', { step: 4, name: SCAN_STEPS[4], status: 'active' });
      await log(scan, 'info', '[Suricata] Querying EVE JSON log for alerts in scan window...');

      const alerts = await getSuricataAlerts(scanStartTime, new Date());

      if (!scan.networkCapture) scan.networkCapture = { suricataAlerts: [], totalPackets: 0 };
      scan.networkCapture.suricataAlerts = alerts;

      if (alerts.length > 0) {
        await log(scan, 'alert', `[Suricata] ⚠ ${alerts.length} IDS alerts triggered!`);
        alerts.forEach(a => {
          emit(scanId, 'scan:progress', {
            level: 'alert',
            message: `[Suricata] ALERT: ${a.signature} (${a.category}) src=${a.srcIp}`,
          });
        });
      } else {
        await log(scan, 'info', '[Suricata] No IDS alerts triggered.');
      }

      emit(scanId, 'scan:step', { step: 4, name: SCAN_STEPS[4], status: 'done' });
    }

    job.progress(80);

    // === STEP 7: Risk Scoring ===
    emit(scanId, 'scan:step', { step: 5, name: SCAN_STEPS[5], status: 'active' });
    await log(scan, 'info', '[Scoring] Computing weighted threat score...');

    const scoreResult = computeRiskScore(scan.signals, riskWeights);
    scan.normalizedSignals = scoreResult.normalizedSignals;
    scan.scoreBreakdown = scoreResult.scoreBreakdown;
    scan.threatScore = scoreResult.threatScore;
    scan.riskLevel = scoreResult.riskLevel;
    scan.recommendedAction = scoreResult.recommendedAction;

    await log(scan, 'info', `[Scoring] ThreatScore=${scan.threatScore} → ${scan.riskLevel}`);
    await log(scan, 'info', `[Scoring] Recommendation: ${scan.recommendedAction}`);

    emit(scanId, 'scan:step', { step: 5, name: SCAN_STEPS[5], status: 'done' });
    job.progress(90);

    // === STEP 8: IoC Extraction ===
    emit(scanId, 'scan:step', { step: 6, name: SCAN_STEPS[6], status: 'active' });
    await log(scan, 'info', '[IoC] Extracting indicators of compromise...');

    const iocs = extractIoCs(
      scan.networkRequests,
      scan.redirectChain,
      scan.signals
    );
    scan.iocs = iocs;

    await log(scan, 'info', `[IoC] Extracted ${iocs.length} indicators.`);
    emit(scanId, 'scan:step', { step: 6, name: SCAN_STEPS[6], status: 'done' });

    // === COMPLETE ===
    scan.status = 'complete';
    scan.completedAt = new Date();
    await scan.save();

    job.progress(100);

    emit(scanId, 'scan:complete', {
      scanId,
      threatScore: scan.threatScore,
      riskLevel: scan.riskLevel,
      iocCount: scan.iocs.length,
      duration: Math.round((scan.completedAt - scan.scanStartedAt) / 1000),
    });

    await log(scan, 'info', `✅ Scan complete. Score: ${scan.threatScore} (${scan.riskLevel})`);

    return {
      threatScore: scan.threatScore,
      riskLevel: scan.riskLevel,
      iocCount: scan.iocs.length,
    };

  } catch (error) {
    console.error(`[Scan ${scanId}] FAILED:`, error.message);

    if (scan) {
      scan.status = 'error';
      scan.errorMessage = error.message;
      scan.completedAt = new Date();
      await scan.save().catch(() => {});
    }

    emit(scanId, 'scan:error', { error: error.message, scanId });

    // Clean up wireshark if running
    if (wiresharkProc) {
      try { wiresharkProc.kill('SIGTERM'); } catch (_) {}
    }

    throw error;
  }
};
