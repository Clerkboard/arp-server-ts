/**
 * Persistence layer for ACP:
 *
 * - **Key Pin Store** (TOFU) -- maps a DID to its pinned public key.
 *   Backed by `data/pins.json`.
 *
 * - **Idempotency Store** -- tracks seen message IDs so duplicate
 *   deliveries are rejected.  In-memory only; entries older than 24 h
 *   are reaped every five minutes.
 */

import fs from 'node:fs';
import path from 'node:path';
import type { KeyPin, KeyPinStore } from './types.js';
import { log } from './logger.js';

// ---------------------------------------------------------------------------
// Key Pin Store
// ---------------------------------------------------------------------------

const TWENTY_FOUR_HOURS = 24 * 60 * 60 * 1000;

export class PinStore {
  private pins: Map<string, KeyPin> = new Map();
  private filePath: string;

  constructor(dataDir: string) {
    this.filePath = path.join(dataDir, 'pins.json');
    this.load();
  }

  /** Read pins from disk (if the file exists). */
  private load(): void {
    if (!fs.existsSync(this.filePath)) return;
    try {
      const raw: KeyPinStore = JSON.parse(fs.readFileSync(this.filePath, 'utf-8'));
      for (const [did, pin] of Object.entries(raw)) {
        this.pins.set(did, pin);
      }
    } catch {
      // Corrupt file -- start fresh
    }
  }

  /** Flush current pins to disk. */
  private save(): void {
    const obj: KeyPinStore = {};
    for (const [did, pin] of this.pins) {
      obj[did] = pin;
    }
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.writeFileSync(this.filePath, JSON.stringify(obj, null, 2), 'utf-8');
  }

  hasPin(did: string): boolean {
    return this.pins.has(did);
  }

  getPin(did: string): KeyPin | undefined {
    return this.pins.get(did);
  }

  setPin(did: string, publicKeyMultibase: string): void {
    this.pins.set(did, {
      publicKeyMultibase,
      firstContact: new Date().toISOString(),
    });
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
