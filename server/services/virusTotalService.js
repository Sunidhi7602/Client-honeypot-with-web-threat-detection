/**
 * HoneyScan VirusTotal v3 Integration
 * Real API calls for IoC enrichment using analyst-configured API key
 */

const axios = require('axios');
const crypto = require('crypto');

const VT_BASE = 'https://www.virustotal.com/api/v3';

const VT_ENDPOINTS = {
  domain: (v) => `${VT_BASE}/domains/${v}`,
  ip: (v) => `${VT_BASE}/ip_addresses/${v}`,
  url: (v) => `${VT_BASE}/urls/${Buffer.from(v).toString('base64').replace(/=+$/, '')}`,
  hash: (v) => `${VT_BASE}/files/${v}`,
  redirect_chain: null,
  email: null,
};

/**
 * Lookup an IoC on VirusTotal
 * @param {string} value - IoC value
 * @param {string} type - IoC type (domain|ip|hash|url)
 * @param {string} apiKey - VirusTotal API key
 */
const virusTotalLookup = async (value, type, apiKey) => {
  if (!apiKey) throw new Error('VirusTotal API key not configured');

  const endpointFn = VT_ENDPOINTS[type];
  if (!endpointFn) {
    return { error: `No VirusTotal endpoint for type: ${type}` };
  }

  const endpoint = endpointFn(value);

  try {
    const response = await axios.get(endpoint, {
      headers: { 'x-apikey': apiKey },
      timeout: 15000,
    });

    const data = response.data?.data?.attributes;
    if (!data) return { error: 'Unexpected VT response format' };

    // Parse last_analysis_stats
    const stats = data.last_analysis_stats || {};
    const positives = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    return {
      positives,
      total,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      scanDate: data.last_analysis_date
        ? new Date(data.last_analysis_date * 1000).toISOString()
        : null,
      permalink: `https://www.virustotal.com/gui/${type === 'hash' ? 'file' : type === 'ip' ? 'ip-address' : type}/${value}`,
      reputation: data.reputation || 0,
      cached: false,
      categories: data.categories || {},
      country: data.country || null,
    };

  } catch (error) {
    if (error.response?.status === 404) {
      return { positives: 0, total: 0, error: 'Not found in VirusTotal database', cached: false };
    }
    if (error.response?.status === 401) {
      throw new Error('Invalid VirusTotal API key');
    }
    if (error.response?.status === 429) {
      throw new Error('VirusTotal API rate limit exceeded. Please wait before retrying.');
    }
    throw new Error(`VirusTotal API error: ${error.message}`);
  }
};

/**
 * Get VirusTotal URL for manual lookup (fallback when no API key)
 */
const getVirusTotalUrl = (value, type) => {
  const paths = {
    domain: `https://www.virustotal.com/gui/domain/${value}`,
    ip: `https://www.virustotal.com/gui/ip-address/${value}`,
    url: `https://www.virustotal.com/gui/url/${Buffer.from(value).toString('base64').replace(/=+$/, '')}`,
    hash: `https://www.virustotal.com/gui/file/${value}`,
  };
  return paths[type] || `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
};

module.exports = { virusTotalLookup, getVirusTotalUrl };
