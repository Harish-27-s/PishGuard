export interface NormalizedURL {
  original: string;
  normalised: string;
  scheme: string;
  host: string;
  registeredDomain: string;
  subdomain: string;
  suffix: string;
  path: string;
  isIp: boolean;
}

export type Verdict = 'Safe' | 'Suspicious' | 'Dangerous';

export type DetectionSource = 'database' | 'rules' | 'ml' | 'combined';

export interface RuleHit {
  id: string;
  category: 'brand_spoof' | 'malware_apk' | 'structure' | 'tld_risk' | 'message_lure' | 'homoglyph';
  name: string;
  points: number;
  explanation: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface LexicalFeatures {
  urlLength: number;
  hostLength: number;
  pathLength: number;
  dotCount: number;
  hyphenCount: number;
  specialCharCount: number;
  digitCount: number;
  digitRatio: number;
  hostEntropy: number;
  domainEntropy: number;
  subdomainCount: number;
  hasIp: boolean;
  hasPunycode: boolean;
  hasApk: boolean;
  lexicalRiskProbability: number;
}

export interface PhishingRecord {
  id?: number | string;
  url: string;
  domain: string;
  source: string;
  dateAdded: string;
  matchType?: 'url' | 'domain';
  threatType?: string;
  targetBrand?: string;
}

export interface DetectionResult {
  verdict: Verdict;
  score: number; // 0 to 100
  reasons: string[];
  source: DetectionSource;
  normalized?: NormalizedURL;
  databaseHit?: PhishingRecord | null;
  ruleHits: RuleHit[];
  lexicalFeatures?: LexicalFeatures;
  advice: string[];
  scamContext?: {
    category?: string;
    detectedBrand?: string;
    officialDomain?: string;
    language?: 'English' | 'Hindi' | 'Hinglish' | 'Tamil' | 'Unknown';
    extractedUrls?: string[];
  };
}

export interface OfficialBrand {
  name: string;
  category: 'Banking' | 'Government' | 'Payments' | 'Utilities' | 'Postal';
  officialDomains: string[];
  keywords: string[];
  logoText: string;
  alertNote?: string;
}
