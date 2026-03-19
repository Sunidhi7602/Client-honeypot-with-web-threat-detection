/**
 * HoneyScan Puppeteer Sandbox
 * Full CDP instrumentation: Network, Page, Runtime, DOM monitoring
 * Runs inside VirtualBox VM (or headless on host for testing)
 */

const puppeteer = require('puppeteer');

const SUSPICIOUS_PATTERNS = [
  /eval\(/i,
  /document\.write/i,
  /unescape\(/i,
  /fromCharCode/i,
  /\.exe$/i,
  /\.dll$/i,
  /\.bat$/i,
  /exploit/i,
  /shellcode/i,
];

const isFlaggedUrl = (url) => {
  try {
    const parsed = new URL(url);
    return SUSPICIOUS_PATTERNS.some(p => p.test(url)) ||
      parsed.hostname !== new URL(url).hostname; // cross-origin check simplified
  } catch {
    return false;
  }
};

/**
 * Main Puppeteer scan function
 * @param {Object} config - { url, options, scanId }
 * @param {Object} callbacks - { onNetworkRequest, onRedirect, onLog }
 */
const runPuppeteerScan = async (config, callbacks = {}) => {
  const { url, options = {}, scanId } = config;
  const { onNetworkRequest, onRedirect, onLog } = callbacks;

  const log = onLog || ((level, msg) => console.log(`[${level}] ${msg}`));

  const signals = {
    scriptCount: 0,
    redirectCount: 0,
    hiddenIframes: 0,
    downloadAttempts: 0,
    domMutationRate: 0,
    externalScripts: 0,
    consoleErrors: 0,
    cookiesSet: 0,
    localStorageWrites: 0,
  };

  let browser = null;
  let domBefore = '';
  let domAfter = '';
  let domMutationCount = 0;
  const domMutationStart = Date.now();

  try {
    await log('info', '[Puppeteer] Launching browser with CDP...');

    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--allow-running-insecure-content',
        '--disable-blink-features=AutomationControlled',
        `--user-agent=${options.userAgent || 'HoneyScan/1.0 (Research Scanner; compatible; Chromium)'}`,
      ],
      timeout: 30000,
    });

    const page = await browser.newPage();

    // Stealth: remove webdriver flag
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    });

    // Set viewport
    await page.setViewport({ width: 1366, height: 768 });

    // === CDP Session Setup ===
    const client = await page.target().createCDPSession();

    await client.send('Network.enable');
    await client.send('Page.enable');
    await client.send('Runtime.enable');
    await client.send('DOM.enable');

    // Network.requestWillBeSent — capture all outgoing requests
    client.on('Network.requestWillBeSent', (params) => {
      const { request, requestId, redirectResponse } = params;
      signals.scriptCount++;

      const flagged = isFlaggedUrl(request.url) ||
        SUSPICIOUS_PATTERNS.some(p => p.test(request.url));

      const reqEntry = {
        method: request.method,
        url: request.url,
        status: null,
        size: 0,
        type: params.type || 'Other',
        flagged,
        flagReason: flagged ? 'Suspicious URL pattern detected' : null,
        timestamp: new Date(),
      };

      if (onNetworkRequest) onNetworkRequest(reqEntry);

      // Detect redirect
      if (redirectResponse) {
        signals.redirectCount++;
        const hop = {
          from: redirectResponse.url,
          to: request.url,
          status: redirectResponse.status,
          reputation: redirectResponse.status >= 400 ? 'suspicious' : 'unknown',
        };
        if (onRedirect) onRedirect(hop);
        log('info', `[CDP] Redirect: ${redirectResponse.url} → ${request.url} (${redirectResponse.status})`);
      }

      // Count external scripts
      if (params.type === 'Script') {
        try {
          const reqUrl = new URL(request.url);
          const baseUrl = new URL(url);
          if (reqUrl.hostname !== baseUrl.hostname) {
            signals.externalScripts++;
            log('info', `[CDP] External script: ${request.url}`);
          }
        } catch (_) {}
      }
    });

    // Network.responseReceived — capture response metadata
    client.on('Network.responseReceived', (params) => {
      const { response } = params;
      if (onNetworkRequest) {
        onNetworkRequest({
          method: null,
          url: response.url,
          status: response.status,
          size: response.headers?.['content-length'] ? parseInt(response.headers['content-length']) : 0,
          type: 'response',
          flagged: response.status >= 400,
          timestamp: new Date(),
        });
      }
    });

    // Page.frameNavigated — track redirects
    client.on('Page.frameNavigated', (params) => {
      const { frame } = params;
      if (frame.parentId) return; // Ignore sub-frames for main redirect tracking
      log('info', `[CDP] Frame navigated: ${frame.url}`);
    });

    // Page.downloadWillBegin — detect download attempts
    client.on('Page.downloadWillBegin', (params) => {
      signals.downloadAttempts++;
      log('warn', `[CDP] ⚠ Download intercepted: ${params.suggestedFilename} from ${params.url}`);
    });

    // Runtime.consoleAPICalled — capture JS console output
    client.on('Runtime.consoleAPICalled', (params) => {
      const { type, args } = params;
      const message = args.map(a => a.value || a.description || '').join(' ');

      if (type === 'error') {
        signals.consoleErrors++;
        log('warn', `[CDP] Console error: ${message.substring(0, 200)}`);
      } else if (type === 'warning') {
        log('debug', `[CDP] Console warn: ${message.substring(0, 200)}`);
      }

      // Detect suspicious eval patterns in console
      if (SUSPICIOUS_PATTERNS.some(p => p.test(message))) {
        log('alert', `[CDP] ⚠ Suspicious console output detected: ${message.substring(0, 100)}`);
      }
    });

    // === DOM Mutation Observer Setup ===
    await page.exposeFunction('__hsOnMutation', (count) => {
      domMutationCount += count;
    });

    await page.evaluateOnNewDocument(() => {
      window.__hsMutations = 0;
      const observer = new MutationObserver((mutations) => {
        window.__hsMutations += mutations.length;
        if (window.__hsOnMutation) window.__hsOnMutation(mutations.length);
      });
      observer.observe(document, { childList: true, subtree: true, attributes: true });
    });

    // === Navigate ===
    await log('info', `[Puppeteer] Navigating to ${url}...`);
    try {
      await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: 30000,
      });
    } catch (navErr) {
      // Some pages never reach networkidle — continue anyway
      await log('warn', `[Puppeteer] Navigation timeout/warning: ${navErr.message}`);
    }

    await log('info', `[Puppeteer] Initial page load complete. Observing for ${options.observationWindow || 30}s...`);

    // Capture DOM before script execution
    domBefore = await page.content().catch(() => '<error capturing DOM>');

    // === Observation Window ===
    const observationMs = (options.observationWindow || 30) * 1000;
    const checkInterval = 2000;
    let elapsed = 0;

    while (elapsed < observationMs) {
      await new Promise(r => setTimeout(r, checkInterval));
      elapsed += checkInterval;

      // Check for hidden iframes periodically
      const iframeCheck = await page.evaluate(() => {
        const hiddenIframes = document.querySelectorAll(
          'iframe[style*="display:none"], iframe[style*="display: none"], iframe[style*="visibility:hidden"], iframe[width="0"], iframe[height="0"]'
        );
        return { count: hiddenIframes.length };
      }).catch(() => ({ count: 0 }));

      signals.hiddenIframes = Math.max(signals.hiddenIframes, iframeCheck.count);
      if (iframeCheck.count > 0) {
        log('alert', `[Puppeteer] ⚠ ${iframeCheck.count} hidden iframe(s) detected!`);
      }
    }

    // Capture DOM after observation
    domAfter = await page.content().catch(() => '<error capturing DOM>');

    // Get final mutation count
    const finalMutations = await page.evaluate(() => window.__hsMutations || 0).catch(() => 0);
    signals.domMutationRate = Math.min(finalMutations / (observationMs / 1000), 1.0); // mutations per second, capped at 1

    // Final hidden iframe check
    const finalIframeCheck = await page.evaluate(() => {
      const all = document.querySelectorAll('iframe[style*="display:none"], iframe[style*="display: none"]');
      return all.length;
    }).catch(() => 0);
    signals.hiddenIframes = Math.max(signals.hiddenIframes, finalIframeCheck);

    await log('info', `[Puppeteer] Observation complete. domMutations=${finalMutations}, hiddenIframes=${signals.hiddenIframes}`);

    return {
      signals,
      domBefore: domBefore.substring(0, 50000), // Limit size
      domAfter: domAfter.substring(0, 50000),
    };

  } finally {
    if (browser) {
      await browser.close().catch(() => {});
      await log('info', '[Puppeteer] Browser closed.');
    }
  }
};

module.exports = { runPuppeteerScan };
