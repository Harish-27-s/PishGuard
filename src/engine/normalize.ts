import { NormalizedURL } from '../types';

const TRACKING_PARAMS = new Set([
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'utm_id',
  'fbclid',
  'gclid',
  'msclkid',
  'dclid',
  'zanpid',
  'igshid',
  'ref',
  'referrer',
  'mc_eid',
  'mc_cid',
]);

const UTM_PREFIX_RE = /^utm_/i;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

// Two-part TLD suffixes commonly found in India and globally
const TWO_PART_TLDS = new Set([
  'co.in',
  'gov.in',
  'nic.in',
  'ac.in',
  'net.in',
  'org.in',
  'gen.in',
  'res.in',
  'edu.in',
  'mil.in',
  'co.uk',
  'org.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'co.nz',
  'co.za',
  'com.br',
  'com.mx',
  'com.sg',
  'edu.sg',
  'gov.sg',
]);

/**
 * Remove tracking parameters from query string
 */
export function stripTracking(queryString: string): string {
  if (!queryString) return '';
  const searchParams = new URLSearchParams(queryString);
  const toDelete: string[] = [];

  searchParams.forEach((_, key) => {
    const lowerKey = key.toLowerCase();
    if (TRACKING_PARAMS.has(lowerKey) || UTM_PREFIX_RE.test(lowerKey)) {
      toDelete.push(key);
    }
  });

  toDelete.forEach((key) => searchParams.delete(key));
  return searchParams.toString();
}

/**
 * Extract registered domain, subdomain, and suffix from a hostname
 */
export function extractDomainParts(hostname: string): {
  registeredDomain: string;
  subdomain: string;
  suffix: string;
} {
  const host = hostname.toLowerCase().trim();
  if (!host || IPV4_RE.test(host) || host.startsWith('[')) {
    return { registeredDomain: host, subdomain: '', suffix: '' };
  }

  const parts = host.split('.');
  if (parts.length === 1) {
    return { registeredDomain: host, subdomain: '', suffix: '' };
  }

  // Check for two-part suffix like co.in, gov.in
  if (parts.length >= 3) {
    const potentialTwoPartSuffix = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    if (TWO_PART_TLDS.has(potentialTwoPartSuffix)) {
      const registeredDomain = `${parts[parts.length - 3]}.${potentialTwoPartSuffix}`;
      const subdomain = parts.slice(0, parts.length - 3).join('.');
      return { registeredDomain, subdomain, suffix: potentialTwoPartSuffix };
    }
  }

  // Default one-part suffix like .com, .in, .xyz
  const suffix = parts[parts.length - 1];
  const registeredDomain = `${parts[parts.length - 2]}.${suffix}`;
  const subdomain = parts.slice(0, parts.length - 2).join('.');

  return { registeredDomain, subdomain, suffix };
}

/**
 * Normalise url and return a NormalizedURL, or null if unparseable.
 * Matches app/normalize.py behavior.
 */
export function normalize(url: string): NormalizedURL | null {
  const raw = url ? url.trim() : '';
  if (!raw) return null;

  // Add scheme if missing so URL parser can split host vs path correctly
  let rawWithScheme = raw;
  if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(raw)) {
    rawWithScheme = 'http://' + raw;
  }

  try {
    const parsed = new URL(rawWithScheme);
    const scheme = (parsed.protocol.replace(':', '') || 'http').toLowerCase();
    const host = (parsed.hostname || '').toLowerCase();

    if (!host) {
      return null;
    }

    // Decode percent-encoding in path once safely
    let path = parsed.pathname;
    try {
      path = decodeURIComponent(path);
    } catch {
      // keep original if invalid percent encoding
    }

    // Strip tracking query params; remove fragment entirely
    const cleanQuery = stripTracking(parsed.search.replace(/^\?/, ''));

    // Rebuild canonical URL
    const queryPart = cleanQuery ? `?${cleanQuery}` : '';
    const portPart = parsed.port && parsed.port !== '80' && parsed.port !== '443' ? `:${parsed.port}` : '';
    const normalised = `${scheme}://${host}${portPart}${path}${queryPart}`;

    const { registeredDomain, subdomain, suffix } = extractDomainParts(host);
    const isIp = IPV4_RE.test(host) || host.startsWith('[');

    return {
      original: url,
      normalised,
      scheme,
      host,
      registeredDomain: registeredDomain || host,
      subdomain,
      suffix,
      path,
      isIp,
    };
  } catch {
    return null;
  }
}

/**
 * Convenience wrapper returning canonical URL string
 */
export function normalizeUrlString(url: string): string {
  const result = normalize(url);
  if (!result) return url.trim();
  return result.normalised;
}
