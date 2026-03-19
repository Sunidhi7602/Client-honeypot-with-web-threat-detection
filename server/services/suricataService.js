/**
 * HoneyScan Suricata Service
 * Parses /var/log/suricata/eve.json for alerts within scan time window
 * Uses Emerging Threats Open ruleset + custom exploit-kit signatures
 */

const fs = require('fs');
const readline = require('readline');
const path = require('path');

const EVE_LOG_PATH = process.env.SURICATA_EVE_LOG || '/var/log/suricata/eve.json';

/**
 * Get Suricata alerts within a time window
 * @param {Date} startTime - Scan start timestamp
 * @param {Date} endTime - Scan end timestamp
 * @returns {Array} Array of structured alert objects
 */
const getSuricataAlerts = async (startTime, endTime) => {
  if (process.env.SKIP_SURICATA === 'true') {
    console.log('[Suricata] SKIP_SURICATA=true — skipping IDS check');
    return [];
  }

  if (!fs.existsSync(EVE_LOG_PATH)) {
    console.warn(`[Suricata] EVE log not found: ${EVE_LOG_PATH}`);
    return [];
  }

  const alerts = [];
  const start = startTime.getTime();
  const end = endTime.getTime();

  try {
    const fileStream = fs.createReadStream(EVE_LOG_PATH);
    const rl = readline.createInterface({ input: fileStream, crlfDelay: Infinity });

    for await (const line of rl) {
      if (!line.trim()) continue;

      let event;
      try {
        event = JSON.parse(line);
      } catch {
        continue;
      }

      // Only process alert events within time window
      if (event.event_type !== 'alert') continue;

      const eventTime = new Date(event.timestamp).getTime();
      if (eventTime < start || eventTime > end) continue;

      const alert = event.alert;
      if (!alert) continue;

      alerts.push({
        signature: alert.signature || 'Unknown Signature',
        severity: alert.severity || 3,
        category: alert.category || 'Uncategorized',
        srcIp: event.src_ip || '',
        destIp: event.dest_ip || '',
        srcPort: event.src_port || 0,
        destPort: event.dest_port || 0,
        protocol: event.proto || 'unknown',
        timestamp: new Date(event.timestamp),
        flowId: event.flow_id?.toString() || '',
        gid: alert.gid,
        rev: alert.rev,
        signatureId: alert.signature_id,
      });
    }

    console.log(`[Suricata] Found ${alerts.length} alerts in scan window [${startTime.toISOString()} → ${endTime.toISOString()}]`);
    return alerts;

  } catch (error) {
    console.error('[Suricata] Error reading EVE log:', error.message);
    return [];
  }
};

/**
 * Tail EVE log for real-time alerting (used for live streaming)
 * @param {Function} onAlert - Callback for new alerts
 * @returns {Function} Cleanup function
 */
const tailEveLog = (onAlert) => {
  if (process.env.SKIP_SURICATA === 'true' || !fs.existsSync(EVE_LOG_PATH)) {
    return () => {};
  }

  const { Tail } = require('tail');
  const tail = new Tail(EVE_LOG_PATH, { follow: true });

  tail.on('line', (line) => {
    try {
      const event = JSON.parse(line);
      if (event.event_type === 'alert' && event.alert) {
        onAlert({
          signature: event.alert.signature,
          severity: event.alert.severity,
          category: event.alert.category,
          srcIp: event.src_ip,
          destIp: event.dest_ip,
          timestamp: new Date(event.timestamp),
        });
      }
    } catch (_) {}
  });

  tail.on('error', (err) => {
    console.error('[Suricata] Tail error:', err.message);
  });

  tail.watch();

  // Return cleanup
  return () => tail.unwatch();
};

/**
 * Check if Suricata is running
 */
const checkSuricataStatus = async () => {
  const { exec } = require('child_process');
  const { promisify } = require('util');
  const execAsync = promisify(exec);

  try {
    const { stdout } = await execAsync('systemctl is-active suricata');
    return { running: stdout.trim() === 'active', evePath: EVE_LOG_PATH };
  } catch {
    return { running: false, evePath: EVE_LOG_PATH };
  }
};

module.exports = { getSuricataAlerts, tailEveLog, checkSuricataStatus };
