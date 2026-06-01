/**
 * Persistence layer for ARP:
 *
 * - **Relation Store** (v0.4.0) -- maps a DID to its relation record,
 *   including pinned key, status, and interaction history.
 *   Backed by `data/relations.json`.
 *
 * - **Idempotency Store** -- tracks seen message IDs so duplicate
 *   deliveries are rejected.  In-memory only; entries older than 24 h
 *   are reaped every five minutes.
 */

import fs from 'node:fs';
import path from 'node:path';
import type { Relation, RelationStatus, RelationStore as RelationStoreMap, TrustLevel } from './types.js';
import { log } from './logger.js';

// ---------------------------------------------------------------------------
// Relation Store (v0.4.0 — replaces PinStore)
// ---------------------------------------------------------------------------

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;
const TWENTY_FOUR_HOURS = 24 * 60 * 60 * 1000;

export class RelationStore {
  private relations: Map<string, Relation> = new Map();
  private filePath: string;

  constructor(dataDir: string) {
    this.filePath = path.join(dataDir, 'relations.json');
    this.load();
  }

  private load(): void {
    // Migrate from old pins.json if relations.json doesn't exist
    const pinsPath = path.join(path.dirname(this.filePath), 'pins.json');
    if (!fs.existsSync(this.filePath) && fs.existsSync(pinsPath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(pinsPath, 'utf-8'));
        for (const [did, pin] of Object.entries(raw)) {
          const p = pin as { publicKeyMultibase: string; firstContact: string };
          this.relations.set(did, {
            peerDid: did,
            pinnedKey: p.publicKeyMultibase,
            status: 'active',
            firstContact: p.firstContact,
            lastActivity: p.firstContact,
            completions: 0,
          });
        }
        this.save();
        log.info(`Migrated ${this.relations.size} pins to relations`);
        return;
      } catch {
        // Fall through
      }
    }

    if (!fs.existsSync(this.filePath)) return;
    try {
      const raw: RelationStoreMap = JSON.parse(fs.readFileSync(this.filePath, 'utf-8'));
      for (const [did, rel] of Object.entries(raw)) {
        this.relations.set(did, rel);
      }
    } catch {
      // Corrupt file — start fresh
    }
  }

  private save(): void {
    const obj: RelationStoreMap = {};
    for (const [did, rel] of this.relations) {
      obj[did] = rel;
    }
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, JSON.stringify(obj, null, 2), 'utf-8');
  }

  hasRelation(did: string): boolean {
    return this.relations.has(did);
  }

  getRelation(did: string): Relation | undefined {
    return this.relations.get(did);
  }

  /** Check if a DID has an active or dormant relation (reactivatable). */
  hasActiveRelation(did: string): boolean {
    const rel = this.relations.get(did);
    return rel !== undefined && (rel.status === 'active' || rel.status === 'dormant');
  }

  /** Get the pinned key for a DID (if relation exists and is not terminated). */
  getPinnedKey(did: string): string | undefined {
    const rel = this.relations.get(did);
    if (!rel || rel.status === 'terminated') return undefined;
    return rel.pinnedKey;
  }

  /** Create a new relation on first contact. */
  createRelation(did: string, publicKeyMultibase: string): void {
    const now = new Date().toISOString();
    this.relations.set(did, {
      peerDid: did,
      pinnedKey: publicKeyMultibase,
      status: 'active',
      firstContact: now,
      lastActivity: now,
      completions: 0,
    });
    this.save();
    log.info('Created relation', { did, status: 'active' });
  }

  /** Record activity on an existing relation (reactivates dormant). */
  touchRelation(did: string): void {
    const rel = this.relations.get(did);
    if (!rel) return;
    const wasStatus = rel.status;
    rel.lastActivity = new Date().toISOString();
    if (rel.status === 'dormant') {
      rel.status = 'active';
      log.info('Reactivated dormant relation', { did });
    }
    this.save();
  }

  /** Terminate a relation (messages rejected after this). */
  terminateRelation(did: string): void {
    const rel = this.relations.get(did);
    if (!rel) return;
    rel.status = 'terminated';
    this.save();
    log.info('Terminated relation', { did });
  }

  /** Compute trust level for a peer (Section 10.7). */
  getTrustLevel(did: string): TrustLevel {
    const rel = this.relations.get(did);
    if (!rel || rel.status === 'terminated') return 'unknown';

    // Check dormancy (90-day threshold)
    if (rel.status === 'active') {
      const inactiveMs = Date.now() - new Date(rel.lastActivity).getTime();
      if (inactiveMs > NINETY_DAYS_MS) {
        rel.status = 'dormant';
        this.save();
      }
    }

    if (rel.status === 'dormant') {
      // Dormancy downgrades by one tier
      if (rel.completions >= 5) return 'known';     // would be trusted → known
      if (rel.completions >= 1) return 'new';        // would be known → new
      return 'unknown';                               // would be new → unknown
    }

    // Active relation
    if (rel.completions >= 5) return 'trusted';
    if (rel.completions >= 1) return 'known';
    return 'new';
  }

  /** Increment completion count for a relation. */
  addCompletion(did: string): void {
    const rel = this.relations.get(did);
    if (!rel) return;
    rel.completions++;
    rel.lastActivity = new Date().toISOString();
    this.save();
  }
}

// ---------------------------------------------------------------------------
// Idempotency Store
// ---------------------------------------------------------------------------

export class IdempotencyStore {
  private seen: Map<string, number> = new Map();
  private timer: ReturnType<typeof setInterval>;

  constructor() {
    // Reap stale entries every 5 minutes
    this.timer = setInterval(() => this.reap(), 5 * 60 * 1000);
    // Allow the process to exit even if the timer is still running
    this.timer.unref();
  }

  hasMessage(id: string): boolean {
    return this.seen.has(id);
  }

  addMessage(id: string): void {
    this.seen.set(id, Date.now());
  }

  private reap(): void {
    const cutoff = Date.now() - TWENTY_FOUR_HOURS;
    let removed = 0;
    for (const [id, ts] of this.seen) {
      if (ts < cutoff) {
        this.seen.delete(id);
        removed++;
      }
    }
    if (removed > 0) {
      log.info(`Reaped ${removed} stale idempotency entries`);
    }
  }

  /** Stop the reap timer (useful for clean shutdown in tests). */
  destroy(): void {
    clearInterval(this.timer);
  }
}
