import { DetectionResult, DetectionSource, LexicalFeatures, NormalizedURL, RuleHit, Verdict } from '../types';
import { normalize } from './normalize';
import { db } from './database';
import { evaluateMessageRules, evaluateUrlRules } from './rules';
import { OFFICIAL_BRANDS } from '../data/officialBrands';

/**
 * Calculates Shannon entropy of a string
 * High entropy (> 3.8) in domain names often indicates randomly generated DGA or phishing domains.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const frequencies: Record<string, number> = {};

  for (let i = 0; i < len; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const count of Object.values(frequencies)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return Number(entropy.toFixed(3));
}

/**
 * Extracts lexical and structural features mirroring the Random Forest ML model
 */
export function extractLexicalFeatures(norm: NormalizedURL): LexicalFeatures {
  const url = norm.normalised;
  const host = norm.host;
  const domain = norm.registeredDomain;
  const path = norm.path;

  const urlLength = url.length;
  const hostLength = host.length;
  const pathLength = path.length;

  const dotCount = (url.match(/\./g) || []).length;
  const hyphenCount = (url.match(/-/g) || []).length;
  const specialChars = (url.match(/[@?&=%_~#]/g) || []).length;
  const digitMatches = host.match(/\d/g) || [];
  const digitCount = digitMatches.length;
  const digitRatio = hostLength > 0 ? Number((digitCount / hostLength).toFixed(3)) : 0;

  const hostEntropy = calculateShannonEntropy(host);
  const domainEntropy = calculateShannonEntropy(domain);
  const subdomainCount = norm.subdomain ? norm.subdomain.split('.').length : 0;

  const hasIp = norm.isIp;
  const hasPunycode = host.includes('xn--') || /[^\u0000-\u007F]/.test(norm.original);
  const hasApk = path.endsWith('.apk') || path.includes('.apk');

  // Compute lexical risk probability (0 to 1.0)
  let riskScore = 0.05;

  if (hasIp) riskScore += 0.45;
  if (hasApk) riskScore += 0.40;
  if (hasPunycode) riskScore += 0.35;
  if (hyphenCount >= 3) riskScore += 0.20;
  if (digitRatio > 0.35) riskScore += 0.25;
  if (domainEntropy > 3.85) riskScore += 0.20;
  if (subdomainCount >= 3) riskScore += 0.15;
  if (urlLength > 75) riskScore += 0.10;
  if (dotCount > 4) riskScore += 0.10;

  const lexicalRiskProbability = Number(Math.min(0.99, riskScore).toFixed(3));

  return {
    urlLength,
    hostLength,
    pathLength,
    dotCount,
    hyphenCount,
    specialCharCount: specialChars,
    digitCount,
    digitRatio,
    hostEntropy,
    domainEntropy,
    subdomainCount,
    hasIp,
    hasPunycode,
    hasApk,
    lexicalRiskProbability,
  };
}

/**
 * Generate actionable citizen guidance based on verdict and reasons
 */
export function generateCitizenAdvice(verdict: Verdict, ruleHits: RuleHit[], brand?: string): string[] {
  const advice: string[] = [];

  if (verdict === 'Dangerous' || verdict === 'Suspicious') {
    advice.push('Do NOT click the link, download attachments, or enter any OTP or banking password.');
    advice.push('Official government websites in India always end with ".gov.in" or ".nic.in".');
    advice.push('Remember: Receiving money through UPI or QR code NEVER requires entering your UPI PIN.');

    const hasApk = ruleHits.some((r) => r.category === 'malware_apk');
    if (hasApk) {
      advice.push('CRITICAL: Do not install APK files received via SMS or WhatsApp. Legitimate apps are only distributed through Google Play Store.');
    }

    if (brand) {
      advice.push(`For official services of ${brand}, search the official verified portal or contact their toll-free helpline directly.`);
    }

    advice.push('If you have suffered financial loss or received a fraudulent link, immediately report to the National Cyber Crime Reporting Portal at 1930 or visit cybercrime.gov.in.');
  } else {
    advice.push('This link does not display known phishing patterns or threat signatures.');
    advice.push('Always check that your browser address bar shows the expected official domain before entering sensitive credentials.');
  }

  return advice;
}

/**
 * Full URL analysis pipeline:
 * Input -> Normalize -> Database Check -> Rules Heuristics -> ML Lexical Features -> Output
 */
export function analyzeUrl(inputUrl: string): DetectionResult {
  const norm = normalize(inputUrl);

  if (!norm) {
    return {
      verdict: 'Suspicious',
      score: 60,
      reasons: ['The entered URL format is malformed or invalid and cannot be reliably parsed.'],
      source: 'rules',
      ruleHits: [],
      advice: ['Double-check the link for typos or invalid formatting before proceeding.'],
    };
  }

  // 1. Database Check (app/database.py)
  const dbHit = db.lookup(norm.normalised, norm.registeredDomain);
  if (dbHit) {
    const reasons = [
      `Exact threat signature found in PhishGuard threat database (Feed: ${dbHit.source}, added on ${dbHit.dateAdded}).`,
      `Matched by ${dbHit.matchType === 'url' ? 'exact URL signature' : 'associated phishing domain'} ('${dbHit.domain}').`,
    ];

    if (dbHit.threatType) {
      reasons.push(`Threat classification: ${dbHit.threatType}.`);
    }

    const ruleHits = evaluateUrlRules(norm);
    const lexical = extractLexicalFeatures(norm);

    return {
      verdict: 'Dangerous',
      score: 100,
      reasons,
      source: 'database',
      normalized: norm,
      databaseHit: dbHit,
      ruleHits,
      lexicalFeatures: lexical,
      advice: generateCitizenAdvice('Dangerous', ruleHits, dbHit.targetBrand),
      scamContext: {
        category: dbHit.threatType || 'Known Phishing Feed',
        detectedBrand: dbHit.targetBrand,
      },
    };
  }

  // 2. Rules Evaluation (app/rules.py)
  const ruleHits = evaluateUrlRules(norm);

  // 3. Lexical ML Features (app/model.py)
  const lexical = extractLexicalFeatures(norm);

  // 4. Combined Scoring (app/scoring.py)
  let rawRulePoints = ruleHits.reduce((acc, h) => acc + h.points, 0);
  let mlPoints = Math.round(lexical.lexicalRiskProbability * 100);

  let combinedScore = 0;
  let source: DetectionSource = 'combined';

  if (ruleHits.length > 0 && mlPoints > 20) {
    combinedScore = Math.min(100, Math.round(rawRulePoints * 0.75 + mlPoints * 0.25));
    source = 'combined';
  } else if (ruleHits.length > 0) {
    combinedScore = Math.min(100, rawRulePoints);
    source = 'rules';
  } else {
    combinedScore = Math.min(100, mlPoints);
    source = mlPoints > 30 ? 'ml' : 'combined';
  }

  // Check if domain is a known official verified brand
  const isOfficialBrandDomain = OFFICIAL_BRANDS.some((b) =>
    b.officialDomains.some((d) => norm.registeredDomain.toLowerCase() === d.toLowerCase())
  );

  if (isOfficialBrandDomain && ruleHits.length === 0) {
    combinedScore = Math.min(combinedScore, 5);
  }

  // Determine Verdict
  let verdict: Verdict = 'Safe';
  if (combinedScore >= 70) {
    verdict = 'Dangerous';
  } else if (combinedScore >= 31) {
    verdict = 'Suspicious';
  } else {
    verdict = 'Safe';
  }

  // Compile Plain-Language Citizen Reasons
  const reasons: string[] = [];
  if (ruleHits.length > 0) {
    ruleHits.forEach((hit) => {
      reasons.push(hit.explanation);
    });
  }

  if (verdict === 'Safe') {
    if (isOfficialBrandDomain) {
      reasons.push(`Verified official domain for ${norm.registeredDomain}. Legitimate service endpoints recognized.`);
    } else {
      reasons.push('Standard domain structure with no known threat signatures or deceptive lexical markers.');
    }
  }

  if (lexical.domainEntropy > 3.8 && !reasons.some((r) => r.includes('entropy'))) {
    reasons.push(`High character randomness detected in domain name (${lexical.domainEntropy} bits entropy), indicating machine-generated registration.`);
  }

  // Detect brand context
  let detectedBrand: string | undefined;
  for (const b of OFFICIAL_BRANDS) {
    if (norm.host.includes(b.keywords[0]) || norm.registeredDomain.includes(b.keywords[0])) {
      detectedBrand = b.name;
      break;
    }
  }

  return {
    verdict,
    score: combinedScore,
    reasons,
    source,
    normalized: norm,
    databaseHit: null,
    ruleHits,
    lexicalFeatures: lexical,
    advice: generateCitizenAdvice(verdict, ruleHits, detectedBrand),
    scamContext: {
      category: ruleHits[0]?.name || (verdict === 'Safe' ? 'Legitimate' : 'General Web Target'),
      detectedBrand,
    },
  };
}

/**
 * Message/SMS text analysis:
 * Evaluates message heuristics + extracts contained URLs and evaluates them
 */
export function analyzeMessage(text: string): DetectionResult {
  const cleanText = text.trim();
  if (!cleanText) {
    return {
      verdict: 'Safe',
      score: 0,
      reasons: ['No text content entered for scanning.'],
      source: 'rules',
      ruleHits: [],
      advice: ['Enter or paste an SMS or messaging app text to inspect for scam indicators.'],
    };
  }

  const msgAnalysis = evaluateMessageRules(cleanText);
  let highestUrlResult: DetectionResult | null = null;

  // Inspect any embedded URLs
  for (const extractedUrl of msgAnalysis.extractedUrls) {
    const urlRes = analyzeUrl(extractedUrl);
    if (!highestUrlResult || urlRes.score > highestUrlResult.score) {
      highestUrlResult = urlRes;
    }
  }

  // Aggregate rule hits
  const allRuleHits = [...msgAnalysis.ruleHits];
  if (highestUrlResult && highestUrlResult.ruleHits) {
    highestUrlResult.ruleHits.forEach((hit) => {
      if (!allRuleHits.some((h) => h.id === hit.id)) {
        allRuleHits.push(hit);
      }
    });
  }

  let baseScore = msgAnalysis.ruleHits.reduce((acc, h) => acc + h.points, 0);

  if (highestUrlResult) {
    if (highestUrlResult.databaseHit) {
      baseScore = 100;
    } else {
      baseScore = Math.max(baseScore, highestUrlResult.score);
    }
  }

  const finalScore = Math.min(100, baseScore);

  let verdict: Verdict = 'Safe';
  if (finalScore >= 70) {
    verdict = 'Dangerous';
  } else if (finalScore >= 31) {
    verdict = 'Suspicious';
  } else {
    verdict = 'Safe';
  }

  const reasons: string[] = [];
  msgAnalysis.ruleHits.forEach((hit) => reasons.push(hit.explanation));

  if (highestUrlResult && highestUrlResult.reasons.length > 0) {
    reasons.push(...highestUrlResult.reasons);
  }

  if (reasons.length === 0) {
    reasons.push('No obvious scam triggers or high-urgency keywords detected in the message text.');
  }

  let source: DetectionSource = 'rules';
  if (highestUrlResult?.databaseHit) {
    source = 'database';
  } else if (highestUrlResult && highestUrlResult.source === 'combined') {
    source = 'combined';
  }

  return {
    verdict,
    score: finalScore,
    reasons: Array.from(new Set(reasons)),
    source,
    normalized: highestUrlResult?.normalized,
    databaseHit: highestUrlResult?.databaseHit,
    ruleHits: allRuleHits,
    lexicalFeatures: highestUrlResult?.lexicalFeatures,
    advice: generateCitizenAdvice(verdict, allRuleHits, msgAnalysis.detectedBrand),
    scamContext: {
      category: msgAnalysis.category,
      detectedBrand: msgAnalysis.detectedBrand,
      language: msgAnalysis.detectedLanguage,
      extractedUrls: msgAnalysis.extractedUrls,
    },
  };
}
