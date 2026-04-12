/**
 * Ed25519 key management, signing, and verification for ARP.
 *
 * Keys are persisted to disk so the agent keeps a stable identity across
 * restarts.  Signing and verification follow the ARP spec: JCS-canonicalise
 * the message (without `signature`), sign / verify the UTF-8 bytes with
 * Ed25519, and encode the signature as multibase (z + base58btc).
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import bs58 from 'bs58';
// canonicalize ships as CJS; import and cast for ESM interop.
import _canonicalize from 'canonicalize';
const canonicalize = _canonicalize as unknown as (obj: unknown) => string | undefined;
import type { ARPMessage, StoredKeys } from './types.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** SPKI DER header for Ed25519 public keys (12 bytes). */
const ED25519_SPKI_HEADER = Buffer.from('302a300506032b6570032100', 'hex');

/** Multicodec prefix for Ed25519 public keys (2 bytes: 0xed 0x01). */
const ED25519_MULTICODEC_PREFIX = Buffer.from([0xed, 0x01]);

// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

/**
 * Extract the raw 32-byte public key from a Node.js KeyObject by exporting
 * the SPKI DER representation and stripping the 12-byte header.
 */
export function rawPublicKey(publicKey: crypto.KeyObject): Buffer {
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  return spki.subarray(spki.length - 32);
}

/**
 * Wrap a raw 32-byte Ed25519 public key in the SPKI DER envelope so that
 * Node.js `crypto.createPublicKey` can import it.
 */
function wrapRawPublicKey(raw: Buffer): Buffer {
  return Buffer.concat([ED25519_SPKI_HEADER, raw]);
}

/**
 * Encode a raw 32-byte public key as multibase with multicodec prefix.
 * Result: z + base58btc( 0xed01 + raw_32_bytes )  →  34 decoded bytes.
 */
export function encodeMultibase(raw: Buffer): string {
  const prefixed = Buffer.concat([ED25519_MULTICODEC_PREFIX, raw]);
  return 'z' + bs58.encode(prefixed);
}

/**
 * Encode raw bytes as multibase WITHOUT multicodec prefix (for signatures).
 */
export function encodeMultibaseRaw(raw: Buffer): string {
  return 'z' + bs58.encode(raw);
}

/**
 * Decode a multibase string (z + base58btc) to raw bytes.
 */
export function decodeMultibase(mb: string): Buffer {
  if (!mb.startsWith('z')) {
    throw new Error(`Unsupported multibase prefix: ${mb[0]}`);
  }
  return Buffer.from(bs58.decode(mb.slice(1)));
}

/**
 * Import an Ed25519 public key from a multibase string into a Node.js
 * KeyObject. Handles both multicodec-prefixed (34 bytes) and raw (32 bytes)
 * formats for backwards compatibility.
 */
export function importPublicKey(keyOrMultibase: string | Buffer): crypto.KeyObject {
  const decoded = typeof keyOrMultibase === 'string'
    ? decodeMultibase(keyOrMultibase)
    : keyOrMultibase;

  let raw: Buffer;
  if (decoded.length === 34 && decoded[0] === 0xed && decoded[1] === 0x01) {
    // Multicodec-prefixed: strip the 2-byte prefix
    raw = decoded.subarray(2);
  } else if (decoded.length === 32) {
    // Raw key (legacy / backwards compat)
    raw = decoded;
  } else {
    throw new Error(
      `Invalid Ed25519 public key: expected 34 bytes (multicodec-prefixed) or 32 bytes (raw), got ${decoded.length}`,
    );
  }

  return crypto.createPublicKey({
    key: wrapRawPublicKey(raw),
    format: 'der',
    type: 'spki',
  });
}

/**
 * Load an existing key pair from disk, or generate a fresh one if no file
 * exists at `keysPath`.  Returns the private KeyObject and the multibase-
 * encoded public key.
 */
export function loadOrCreateKeys(
  dataDir: string,
): { privateKey: crypto.KeyObject; publicKeyMultibase: string } {
  const keysPath = path.join(dataDir, 'keys.json');

  if (fs.existsSync(keysPath)) {
    const stored: StoredKeys = JSON.parse(fs.readFileSync(keysPath, 'utf-8'));
    const privateKey = crypto.createPrivateKey(stored.privateKeyPem);
    return { privateKey, publicKeyMultibase: stored.publicKeyMultibase };
  }

  // Generate a new Ed25519 key pair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyMultibase = encodeMultibase(rawPublicKey(publicKey));
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

  // Persist to disk
  fs.mkdirSync(dataDir, { recursive: true });
  const stored: StoredKeys = { privateKeyPem, publicKeyMultibase };
  fs.writeFileSync(keysPath, JSON.stringify(stored, null, 2), 'utf-8');

  return { privateKey, publicKeyMultibase };
}

// ---------------------------------------------------------------------------
// Signing & verification
// ---------------------------------------------------------------------------

/**
 * Canonicalise the message (excluding `signature`) per RFC 8785 (JCS).
 */
function canonicalPayload(message: Omit<ARPMessage, 'signature'> & { signature?: string }): Buffer {
  // Shallow-copy, strip signature
  const { signature: _sig, ...rest } = message;
  const canonical = canonicalize(rest);
  if (canonical === undefined) {
    throw new Error('JCS canonicalization returned undefined');
  }
  return Buffer.from(canonical, 'utf-8');
}

/**
 * Sign an ARP message.  Mutates the object by adding a `signature` field
 * and returns the same object for convenience.
 */
export function signMessage(
  message: ARPMessage,
  privateKey: crypto.KeyObject,
): ARPMessage {
  const payload = canonicalPayload(message);
  const sig = crypto.sign(null, payload, privateKey);
  message.signature = encodeMultibaseRaw(sig);
  return message;
}

/**
 * Verify the signature on an ARP message.  Returns `true` when valid.
 */
export function verifyMessage(
  message: ARPMessage,
  publicKey: crypto.KeyObject,
): boolean {
  if (!message.signature) return false;

  const sigBytes = decodeMultibase(message.signature);
  const payload = canonicalPayload(message);
  return crypto.verify(null, payload, publicKey, sigBytes);
}
