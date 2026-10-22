import { PhishingRecord } from '../types';
import { INITIAL_PHISHING_DB, DB_STATS_METADATA } from '../data/seedThreats';
import { normalizeUrlString } from './normalize';

const STORAGE_KEY = 'phishguard_threat_db_v1';

class PhishingDatabase {
  private records: PhishingRecord[] = [];

  constructor() {
    this.init();
  }

  private init() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed) && parsed.length > 0) {
          this.records = parsed;
          return;
        }
      }
    } catch {
      // ignore localStorage errors (e.g., in private mode or SSR)
    }
    this.records = [...INITIAL_PHISHING_DB];
  }

  private save() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.records));
    } catch {
      // ignore
    }
  }

  /**
   * Look up a URL in the known-phishing database.
   * Matches app/database.py lookup():
   * Checks by normalised URL first (exact match), then by registered domain.
   */
  public lookup(normalisedUrl: string, registeredDomain: string): PhishingRecord | null {
    if (!normalisedUrl && !registeredDomain) return null;

    const cleanNorm = normalisedUrl ? normalizeUrlString(normalisedUrl).toLowerCase() : '';
    const cleanDomain = (registeredDomain || '').toLowerCase();

    // 1. Exact URL match
    const exactMatch = this.records.find((rec) => {
      const recNorm = normalizeUrlString(rec.url).toLowerCase();
      return recNorm === cleanNorm;
    });

    if (exactMatch) {
      return {
        ...exactMatch,
        matchType: 'url',
      };
    }

    // 2. Domain match (catches URL variations of a known phishing domain)
    if (cleanDomain) {
      const domainMatch = this.records.find((rec) => {
        const recDomain = (rec.domain || '').toLowerCase();
        return recDomain === cleanDomain;
      });

      if (domainMatch) {
        return {
          ...domainMatch,
          matchType: 'domain',
        };
      }
    }

    return null;
  }

  /**
   * Return total count and breakdown by source
   */
  public dbStats(): {
    total: number;
    activeRecordsCount: number;
    bySource: Record<string, number>;
    lastSynced: string;
  } {
    const bySource: Record<string, number> = { ...DB_STATS_METADATA.bySource };

    // tally any user-added records
    this.records.forEach((rec) => {
      const src = rec.source || 'Manual User Report';
      bySource[src] = (bySource[src] || 0) + 1;
    });

    return {
      total: DB_STATS_METADATA.databaseTotal + this.records.length,
      activeRecordsCount: this.records.length,
      bySource,
      lastSynced: DB_STATS_METADATA.lastSynced,
    };
  }

  /**
   * Get all active records for browsing and searching
   */
  public getAllRecords(): PhishingRecord[] {
    return [...this.records];
  }

  /**
   * Add a new threat record
   */
  public insertThreat(threat: Omit<PhishingRecord, 'id'>): PhishingRecord {
    const newRecord: PhishingRecord = {
      ...threat,
      id: Date.now(),
      url: normalizeUrlString(threat.url),
    };
    this.records.unshift(newRecord);
    this.save();
    return newRecord;
  }

  /**
   * Reset to default seed records
   */
  public resetToDefault(): void {
    this.records = [...INITIAL_PHISHING_DB];
    this.save();
  }
}

export const db = new PhishingDatabase();
