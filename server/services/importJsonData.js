const fs = require('fs');
const path = require('path');
const Scan = require('../models/Scan');

const DATA_DIR = path.join(__dirname, '..', 'data');

const asArray = (payload) => {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.documents)) return payload.documents;
  if (Array.isArray(payload?.scans)) return payload.scans;
  if (payload && typeof payload === 'object' && payload.url) return [payload];
  return [];
};

const sanitizeIoCs = (iocs = []) =>
  iocs
    .filter((ioc) => ioc && typeof ioc.type === 'string' && typeof ioc.value === 'string' && ioc.value.trim())
    .map((ioc) => ({
      ...ioc,
      value: ioc.value.trim(),
    }));

const normalizeScanDoc = (doc) => {
  const normalized = { ...doc };

  if (!normalized.url || typeof normalized.url !== 'string') {
    throw new Error('Each scan document must include a string "url" field.');
  }

  normalized.iocs = sanitizeIoCs(normalized.iocs);
  normalized.status = normalized.status || 'complete';
  normalized.scanType = normalized.scanType || 'quick';

  return normalized;
};

const importJsonFiles = async ({ connection, clearExisting = false } = {}) => {
  if (!connection) {
    throw new Error('A mongoose connection is required.');
  }

  if (!fs.existsSync(DATA_DIR)) {
    return { importedFiles: [], insertedCount: 0 };
  }

  const files = fs.readdirSync(DATA_DIR)
    .filter((file) => file.toLowerCase().endsWith('.json'))
    .sort();

  if (files.length === 0) {
    return { importedFiles: [], insertedCount: 0 };
  }

  const ImportScan = connection.model('Scan', Scan.schema);

  if (clearExisting) {
    await ImportScan.deleteMany({});
    console.log('[JSON Import] Cleared existing scans');
  }

  let insertedCount = 0;
  const importedFiles = [];

  for (const file of files) {
    const fullPath = path.join(DATA_DIR, file);
    const raw = fs.readFileSync(fullPath, 'utf8');
    const payload = JSON.parse(raw);
    const docs = asArray(payload).map(normalizeScanDoc);

    if (docs.length === 0) {
      console.log(`[JSON Import] Skipped ${file}: no scan documents found`);
      continue;
    }

    await ImportScan.insertMany(docs);
    insertedCount += docs.length;
    importedFiles.push({ file, count: docs.length });
    console.log(`[JSON Import] Imported ${docs.length} scan(s) from ${file}`);
  }

  return { importedFiles, insertedCount };
};

module.exports = { DATA_DIR, importJsonFiles };
