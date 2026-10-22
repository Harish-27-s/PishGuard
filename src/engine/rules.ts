import { NormalizedURL, RuleHit } from '../types';
import { OFFICIAL_BRANDS } from '../data/officialBrands';

const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'work',
  'click',
  'buzz',
  'live',
  'link',
  'tk',
  'ml',
  'ga',
  'cf',
  'gq',
  'site',
  'fun',
  'club',
  'shop',
  'icu',
  'monster',
  'fit',
  'rest',
]);

const GOVERNMENT_KEYWORDS = ['gov', 'nic', 'echallan', 'parivahan', 'uidai', 'aadhaar', 'incometax', 'epfo', 'indiapost'];

/**
 * Evaluates rule-based heuristics on a normalized URL
 */
export function evaluateUrlRules(norm: NormalizedURL): RuleHit[] {
  const hits: RuleHit[] = [];
  const host = norm.host.toLowerCase();
  const path = norm.path.toLowerCase();
  const domain = norm.registeredDomain.toLowerCase();

  // 1. Numerical IP Host
  if (norm.isIp) {
    hits.push({
      id: 'rule_ip_host',
      category: 'structure',
      name: 'Numerical IP Address in Host',
      points: 45,
      explanation: 'The link uses a raw IP address (' + host + ') instead of a registered domain. Legitimate financial and government portals never operate on raw IP links.',
      severity: 'high',
    });
  }

  // 2. Direct APK / Executable download lure
  if (path.endsWith('.apk') || path.includes('.apk') || path.endsWith('.exe') || path.endsWith('.bat')) {
    hits.push({
      id: 'rule_apk_download',
      category: 'malware_apk',
      name: 'Direct Android APK Download Lure',
      points: 55,
      explanation: 'Direct APK file download detected (' + path + '). Indian cybercriminals use malicious APKs to intercept bank OTPs and steal SMS credentials. Official apps must only be installed via Google Play Store.',
      severity: 'critical',
    });
  }

  // 3. Indian Brand Impersonation / Typosquatting
  let impersonatedBrand: string | null = null;
  for (const brand of OFFICIAL_BRANDS) {
    const isOfficial = brand.officialDomains.some((d) => domain === d.toLowerCase() || host.endsWith('.' + d.toLowerCase()));
    if (isOfficial) {
      // Legit official domain
      continue;
    }

    const matchedKeyword = brand.keywords.find((kw) => {
      // keyword appears in host (excluding official suffix), domain, or first directory segment of path
      return host.includes(kw) || path.includes('/' + kw);
    });

    if (matchedKeyword) {
      impersonatedBrand = brand.name;
      hits.push({
        id: `rule_spoof_${brand.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
        category: 'brand_spoof',
        name: `Brand Impersonation: ${brand.name}`,
        points: 60,
        explanation: `Unofficial domain '${domain}' uses the name of '${brand.name}'. The verified official domain is: ${brand.officialDomains[0]}.`,
        severity: 'critical',
      });
      break;
    }
  }

  // 4. Fake Government Portal Heuristic
  const claimsGov = GOVERNMENT_KEYWORDS.some((kw) => host.includes(kw));
  const isActualGovDomain = norm.suffix === 'gov.in' || norm.suffix === 'nic.in' || host.endsWith('.gov.in') || host.endsWith('.nic.in');

  if (claimsGov && !isActualGovDomain && !impersonatedBrand) {
    hits.push({
      id: 'rule_fake_gov',
      category: 'brand_spoof',
      name: 'Deceptive Indian Government Mimicry',
      points: 50,
      explanation: `URL attempts to look like an Indian Government portal (${host}) but lacks the official '.gov.in' or '.nic.in' sovereign domain authorization.`,
      severity: 'high',
    });
  }

  // 5. High-Abuse / Suspicious TLD
  if (SUSPICIOUS_TLDS.has(norm.suffix)) {
    const hasSensitiveContext = claimsGov || impersonatedBrand || /login|bank|kyc|verify|update|secure|pay|card|account/i.test(host + path);
    hits.push({
      id: 'rule_suspicious_tld',
      category: 'tld_risk',
      name: `High-Risk TLD (.${norm.suffix})`,
      points: hasSensitiveContext ? 35 : 20,
      explanation: `The domain suffix '.${norm.suffix}' is heavily abused by phishing operators due to cheap anonymous registrations.`,
      severity: hasSensitiveContext ? 'high' : 'medium',
    });
  }

  // 6. Homoglyph / Punycode (IDN) Attack
  if (host.includes('xn--') || /[^\u0000-\u007F]/.test(norm.original)) {
    hits.push({
      id: 'rule_punycode_homoglyph',
      category: 'homoglyph',
      name: 'Punycode / Homoglyph Domain Deception',
      points: 55,
      explanation: 'Uses internationalized character encoding (Punycode `xn--`) or foreign alphabet lookalikes designed to visually deceive human eyes into misreading the domain.',
      severity: 'critical',
    });
  }

  // 7. Structural Anomalies
  // 7a. Excessive Hyphens (e.g. sbi-kyc-pan-update-online.com)
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    hits.push({
      id: 'rule_hyphen_deception',
      category: 'structure',
      name: 'Excessive Hyphenation in Domain',
      points: 25,
      explanation: `Domain contains ${hyphenCount} hyphens ('${domain}'). Legitimate institutions rarely use chained hyphenated domains for public customer portals.`,
      severity: 'medium',
    });
  }

  // 7b. Embedded Credentials / '@' Symbol Deception
  if (norm.original.includes('@')) {
    hits.push({
      id: 'rule_at_symbol',
      category: 'structure',
      name: 'Embedded Credentials / @ Symbol Deception',
      points: 50,
      explanation: 'The URL includes an "@" symbol. Browsers interpret the portion before "@" as login credentials, deceiving users about the destination host.',
      severity: 'critical',
    });
  }

  // 7c. Deep Subdomain Stacking
  if (norm.subdomain) {
    const subParts = norm.subdomain.split('.');
    if (subParts.length >= 3) {
      hits.push({
        id: 'rule_deep_subdomains',
        category: 'structure',
        name: 'Excessive Subdomain Depth',
        points: 20,
        explanation: `Subdomain nesting has ${subParts.length} levels ('${norm.subdomain}'), a frequent indicator of multi-level phishing cloaking.`,
        severity: 'low',
      });
    }
  }

  return hits;
}

export interface MessageAnalysisResult {
  ruleHits: RuleHit[];
  category: string;
  detectedBrand?: string;
  detectedLanguage: 'English' | 'Hindi' | 'Hinglish' | 'Tamil' | 'Unknown';
  extractedUrls: string[];
}

/**
 * Evaluates message heuristics for SMS and messaging apps (WhatsApp / Telegram)
 * Covering Indian scam templates: KYC, e-Challan, Electricity, KBC, and vernacular cues.
 */
export function evaluateMessageRules(text: string): MessageAnalysisResult {
  const hits: RuleHit[] = [];
  const lower = text.toLowerCase();

  // Extract URLs
  const urlRegex = /(https?:\/\/[^\s]+|[a-zA-Z0-9-]+\.(?:com|in|gov\.in|net|xyz|top|live|click|site|org|info|biz)[^\s]*)/gi;
  const matches = text.match(urlRegex) || [];
  const extractedUrls = Array.from(new Set(matches.map((u) => u.replace(/[.,;!?]+$/, ''))));

  // Language Detection
  let detectedLanguage: 'English' | 'Hindi' | 'Hinglish' | 'Tamil' | 'Unknown' = 'English';
  if (/[\u0B80-\u0BFF]/.test(text)) {
    detectedLanguage = 'Tamil';
  } else if (/[\u0900-\u097F]/.test(text)) {
    detectedLanguage = 'Hindi';
  } else if (/aapka|karein|band ho|bijli|turant|kripya|sampark|bhejein|paisa/i.test(text)) {
    detectedLanguage = 'Hinglish';
  }

  let category = 'General Message';
  let detectedBrand: string | undefined;

  // 1. Urgent KYC / Bank Account Freeze Scam
  const kycKeywords = [
    'kyc pending',
    'account blocked',
    'account suspended',
    'pan card',
    'pan update',
    'within 24 hours',
    'deactivated',
    'netbanking blocked',
    'வங்கி கணக்கு',
    'முடக்கப்படும்',
    'புதுப்பிக்க',
    'खाता बंद',
    'केवाईसी',
  ];
  const hasKycLure = kycKeywords.some((k) => lower.includes(k) || text.includes(k));
  if (hasKycLure) {
    category = 'Bank KYC & Account Freeze Lure';
    hits.push({
      id: 'msg_kyc_freeze',
      category: 'message_lure',
      name: 'Urgent Bank / KYC Suspension Threat',
      points: 50,
      explanation: 'Message uses fear and artificial urgency claiming your bank account or PAN card is blocked or pending KYC. Indian banks NEVER threaten immediate account suspension via SMS with external links.',
      severity: 'critical',
    });
  }

  // 2. Fake Traffic e-Challan Scam
  const challanKeywords = [
    'challan',
    'traffic violation',
    'court notice',
    'echallan',
    'impounded',
    'parivahan notice',
    'இ-சலான்',
    'போக்குவரத்து',
    'चालान',
  ];
  if (challanKeywords.some((k) => lower.includes(k) || text.includes(k))) {
    category = 'Fake Traffic e-Challan Notice';
    detectedBrand = 'Parivahan / e-Challan';
    hits.push({
      id: 'msg_traffic_challan',
      category: 'message_lure',
      name: 'Fake Police / Traffic e-Challan Intimidation',
      points: 55,
      explanation: 'Claims traffic violation fines or court action. Scammers send fake challan links (often leading to credential stealers or malicious APKs). Real challans must only be checked on echallan.parivahan.gov.in.',
      severity: 'critical',
    });
  }

  // 3. Electricity Bill Disconnection Scam
  const electricityKeywords = [
    'electricity',
    'power will be disconnected',
    'light cut',
    'bill unpaid',
    'bijli bill',
    'light will be disconnected',
    'at 9:30 pm',
    'power bill',
    'மின்சாரம்',
    'துண்டிக்கப்படும்',
    'மின் கட்டணம்',
    'बिजली बिल',
  ];
  if (electricityKeywords.some((k) => lower.includes(k) || text.includes(k))) {
    category = 'Electricity Disconnection Scam';
    detectedBrand = 'Electricity Board';
    hits.push({
      id: 'msg_electricity_scam',
      category: 'message_lure',
      name: 'Electricity Power Disconnection Threat',
      points: 55,
      explanation: 'Infamous "Electricity Disconnection" scam script claiming power will be disconnected tonight. The phone numbers or links provided belong to cyber fraudsters attempting remote screen-sharing fraud.',
      severity: 'critical',
    });
  }

  // 4. Fake Lottery / Cashback / Scratch Card
  const lotteryKeywords = [
    'won rs',
    'cashback',
    'scratch card',
    'kbc lottery',
    'lucky draw',
    'pm kisan 2000',
    'claim now',
    'free recharge',
    'பரிசு',
    'ரூபாய்',
    'लॉटरी',
    'इनाम',
  ];
  if (lotteryKeywords.some((k) => lower.includes(k) || text.includes(k))) {
    category = 'Lottery / Cashback Scam';
    hits.push({
      id: 'msg_lottery_reward',
      category: 'message_lure',
      name: 'Fake Lottery / UPI Cashback Lure',
      points: 40,
      explanation: 'Offers unexpected cash rewards, UPI cashback, or government subsidies. Fraudsters use these to trick victims into scanning QR codes or entering UPI PINs.',
      severity: 'high',
    });
  }

  // 5. Presence of Suspicious Link or APK in Message
  const hasApkMention = /apk|download app|\.apk/i.test(text);
  if (hasApkMention) {
    hits.push({
      id: 'msg_apk_lure',
      category: 'malware_apk',
      name: 'Message Urging APK Download',
      points: 50,
      explanation: 'The text encourages downloading an APK application. Never install applications outside Google Play Store upon receiving an unsolicited message.',
      severity: 'critical',
    });
  }

  // Identify brand mentions in message
  for (const b of OFFICIAL_BRANDS) {
    if (b.keywords.some((kw) => lower.includes(kw))) {
      detectedBrand = detectedBrand || b.name;
    }
  }

  return {
    ruleHits: hits,
    category,
    detectedBrand,
    detectedLanguage,
    extractedUrls,
  };
}
