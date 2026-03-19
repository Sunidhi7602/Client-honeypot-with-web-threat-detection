/**
 * HoneyScan Wireshark Service
 * Live packet capture via tshark on vboxnet0 bridge interface
 * Parses .pcap to JSON, extracts protocol breakdown, flags suspicious IPs
 */

const { spawn, exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
const path = require('path');
const fs = require('fs');

const CAPTURE_DIR = process.env.CAPTURE_DIR || path.join(__dirname, '../captures');
const INTERFACE = process.env.WIRESHARK_INTERFACE || 'vboxnet0';

// Known threat feed IPs (simplified — in production, load from file/DB)
const THREAT_FEED_IPS = new Set([
  '185.220.101.', '194.165.16.', '45.33.32.', // Tor exits, known C2 ranges (prefixes)
]);

const isSuspiciousIP = (ip) => {
  return Array.from(THREAT_FEED_IPS).some(prefix => ip.startsWith(prefix));
};

/**
 * Start tshark capture process
 * @param {string} scanId
 * @returns {ChildProcess}
 */
const startWiresharkCapture = async (scanId) => {
  if (process.env.SKIP_WIRESHARK === 'true') {
    console.log('[Wireshark] SKIP_WIRESHARK=true — skipping capture');
    return null;
  }

  // Ensure capture dir exists
  if (!fs.existsSync(CAPTURE_DIR)) {
    fs.mkdirSync(CAPTURE_DIR, { recursive: true });
  }

  const pcapPath = path.join(CAPTURE_DIR, `${scanId}.pcap`);

  const args = [
    '-i', INTERFACE,
    '-w', pcapPath,
    '-q', // Quiet
    // Capture filter: VM traffic only
    '-f', `host ${process.env.VBOX_VM_IP || '192.168.56.101'}`,
  ];

  console.log(`[Wireshark] Starting: tshark ${args.join(' ')}`);

  const proc = spawn('tshark', args, {
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  proc.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    if (!msg.includes('packets captured') && !msg.includes('Capturing on')) {
      console.warn('[Wireshark]', msg);
    }
  });

  proc.on('error', (err) => {
    console.error('[Wireshark] Process error:', err.message);
  });

  // Store pcap path on process for later reference
  proc.pcapPath = pcapPath;

  console.log(`[Wireshark] Capture started → ${pcapPath}`);
  return proc;
};

/**
 * Stop capture and parse the pcap file
 * @param {ChildProcess} proc
 * @param {string} scanId
 * @returns {Object} parsed capture data
 */
const stopWiresharkCapture = async (proc, scanId) => {
  if (!proc) {
    return getEmptyCapture(scanId);
  }

  // Gracefully stop tshark
  proc.kill('SIGTERM');
  await new Promise(r => setTimeout(r, 2000)); // Allow final writes

  const pcapPath = proc.pcapPath || path.join(CAPTURE_DIR, `${scanId}.pcap`);

  if (!fs.existsSync(pcapPath)) {
    console.warn('[Wireshark] pcap file not found:', pcapPath);
    return getEmptyCapture(scanId);
  }

  return parsePcapFile(pcapPath, scanId);
};

/**
 * Parse pcap file using tshark -T json
 */
const parsePcapFile = async (pcapPath, scanId) => {
  try {
    const { stdout } = await execAsync(
      `tshark -r "${pcapPath}" -T json -q 2>/dev/null`,
      { timeout: 60000, maxBuffer: 50 * 1024 * 1024 }
    );

    let packets = [];
    try {
      packets = JSON.parse(stdout);
    } catch {
      console.warn('[Wireshark] Could not parse tshark JSON output');
    }

    const stats = analyzePackets(packets);
    return { ...stats, pcapPath, scanId };

  } catch (error) {
    console.error('[Wireshark] Parse error:', error.message);
    return getEmptyCapture(scanId, pcapPath);
  }
};

/**
 * Analyze parsed packets for protocol breakdown and suspicious IPs
 */
const analyzePackets = (packets) => {
  const protocolBreakdown = { http: 0, https: 0, dns: 0, other: 0 };
  const ipCounts = {};
  let suspiciousPackets = 0;

  packets.forEach(pkt => {
    try {
      const layers = pkt._source?.layers || {};

      // Protocol detection
      if (layers.http) protocolBreakdown.http++;
      else if (layers.tls || layers['ssl']) protocolBreakdown.https++;
      else if (layers.dns) protocolBreakdown.dns++;
      else protocolBreakdown.other++;

      // IP tracking
      const srcIp = layers.ip?.['ip.src'];
      const dstIp = layers.ip?.['ip.dst'];

      if (srcIp) {
        ipCounts[srcIp] = (ipCounts[srcIp] || 0) + 1;
        if (isSuspiciousIP(srcIp)) suspiciousPackets++;
      }
      if (dstIp) {
        ipCounts[dstIp] = (ipCounts[dstIp] || 0) + 1;
        if (isSuspiciousIP(dstIp)) suspiciousPackets++;
      }
    } catch (_) {}
  });

  // Top talkers
  const topTalkers = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([ip, packets]) => ({ ip, packets }));

  return {
    totalPackets: packets.length,
    suspiciousPackets,
    protocolBreakdown,
    topTalkers,
  };
};

const getEmptyCapture = (scanId, pcapPath = null) => ({
  totalPackets: 0,
  suspiciousPackets: 0,
  pcapPath,
  protocolBreakdown: { http: 0, https: 0, dns: 0, other: 0 },
  topTalkers: [],
  scanId,
});

module.exports = { startWiresharkCapture, stopWiresharkCapture, parsePcapFile };
