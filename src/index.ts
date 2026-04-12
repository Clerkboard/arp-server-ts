/**
 * ACP Reference Server -- TypeScript / Express
 *
 * Implements a single "echo" agent that speaks the Agent Communication
 * Protocol.  Routes:
 *
 *   GET  /{name}/did.json              -- DID document
 *   GET  /.well-known/acp/{name}.json  -- Agent Card
 *   GET  /.well-known/acp/index.json   -- Agent index
 *   POST /{name}/inbox                 -- Message inbox
 */

import 'dotenv/config';
import crypto from 'node:crypto';
import express, { type Request, type Response } from 'express';
import {
  loadOrCreateKeys,
  signMessage,
  verifyMessage,
  importPublicKey,
  encodeMultibase,
  decodeMultibase,
} from './crypto.js';
import { PinStore, IdempotencyStore } from './store.js';
import { log } from './logger.js';
import type {
  ACPMessage,
  ACPErrorCode,
  DIDDocument,
  AgentCard,
  AgentIndex,
} from './types.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const AGENT_NAME = process.env.ACP_AGENT_NAME ?? 'echo';
const DOMAIN = process.env.ACP_DOMAIN ?? 'localhost';
const PORT = Number(process.env.ACP_PORT ?? 3141);
const DATA_DIR = process.env.ACP_DATA_DIR ?? './data';

const SCHEME = DOMAIN === 'localhost' ? 'http' : 'https';
const BASE_URL = DOMAIN === 'localhost'
  ? `${SCHEME}://${DOMAIN}:${PORT}`
  : `${SCHEME}://${DOMAIN}`;

const AGENT_DID = `did:web:${DOMAIN}:${AGENT_NAME}`;

const MAX_MESSAGE_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

// ---------------------------------------------------------------------------
// Bootstrap keys & stores
// ---------------------------------------------------------------------------

const { privateKey, publicKeyMultibase } = loadOrCreateKeys(DATA_DIR);
const pinStore = new PinStore(DATA_DIR);
const idempotencyStore = new IdempotencyStore();

// ---------------------------------------------------------------------------
// contentRef validation (ACP v0.3)
// ---------------------------------------------------------------------------

/**
 * Private-IP hostname check for SSRF prevention.
 * Rejects localhost, loopback, and RFC-1918 addresses.
 */
function isPrivateHost(hostname: string): boolean {
  // Normalize: URL.hostname strips brackets from IPv6, lowercase
  const h = hostname.toLowerCase();

  // Loopback and reserved
  if (['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]'].includes(h)) return true;

  // IPv6-mapped IPv4 — dotted form (::ffff:127.0.0.1)
  const v4Mapped = h.match(/^(?:\[?)::ffff:(\d+\.\d+\.\d+\.\d+)(?:\]?)$/);
  if (v4Mapped) return isPrivateHost(v4Mapped[1]);

  // IPv6-mapped IPv4 — hex form (Node.js normalizes to ::ffff:7f00:1)
  const v4Hex = h.match(/^(?:\[?)::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?:\]?)$/);
  if (v4Hex) {
    const hi = parseInt(v4Hex[1], 16);
    const lo = parseInt(v4Hex[2], 16);
    const ip = `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
    return isPrivateHost(ip);
  }

  // IPv6 link-local (fe80::) and unique-local (fc00::, fd00::)
  if (h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) return true;

  // IPv4 private ranges
  if (h.startsWith('10.')) return true;
  if (h.startsWith('192.168.')) return true;
  if (h.startsWith('172.')) {
    const second = parseInt(h.split('.')[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  // 169.254.x.x link-local
  if (h.startsWith('169.254.')) return true;

  return false;
}

const HEX64_RE = /^[0-9a-fA-F]{64}$/;

/**
 * Recursively walk `body` and validate every `contentRef` object.
 * Returns an error message string if invalid, or null if everything is fine.
 */
export function validateContentRefs(body: unknown): string | null {
  if (body === null || body === undefined || typeof body !== 'object') {
    return null;
  }

  if (Array.isArray(body)) {
    for (const item of body) {
      const err = validateContentRefs(item);
      if (err) return err;
    }
    return null;
  }

  const obj = body as Record<string, unknown>;

  if ('contentRef' in obj && obj.contentRef !== null && typeof obj.contentRef === 'object') {
    const ref = obj.contentRef as Record<string, unknown>;

    // url — required, must be https, must not target private IPs
    if (typeof ref.url !== 'string' || ref.url === '') {
      return 'contentRef.url is required and must be a string';
    }
    if (!ref.url.startsWith('https://')) {
      return 'contentRef.url must start with https://';
    }
    let hostname: string;
    try {
      hostname = new URL(ref.url).hostname;
    } catch {
      return `contentRef.url is not a valid URL: ${ref.url}`;
    }
    if (isPrivateHost(hostname)) {
      return `contentRef.url must not reference a private/loopback address: ${hostname}`;
    }

    // sha256 — required, 64 hex chars
    if (typeof ref.sha256 !== 'string' || !HEX64_RE.test(ref.sha256)) {
      return 'contentRef.sha256 is required and must be a 64-character hex string';
    }

    // size — required, positive integer
    if (typeof ref.size !== 'number' || !Number.isInteger(ref.size) || ref.size <= 0) {
      return 'contentRef.size is required and must be a positive integer';
    }

    // mediaType — optional, no validation needed
  }

  // Recurse into all values
  for (const value of Object.values(obj)) {
    const err = validateContentRefs(value);
    if (err) return err;
  }

  return null;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function newMessageId(): string {
  return `msg_${crypto.randomUUID()}`;
}

function nowISO(): string {
  return new Date().toISOString();
}

/** Build and sign an ACP error response. */
function errorResponse(
  to: string,
  correlationId: string | undefined,
  code: ACPErrorCode,
  message: string,
  retryable: boolean,
): ACPMessage {
  const msg: ACPMessage = {
    acp: '1.0',
    id: newMessageId(),
    type: 'error',
    from: AGENT_DID,
    to,
    correlationId: correlationId ?? '',
    createdAt: nowISO(),
    body: { code, message, retryable },
  };
  return signMessage(msg, privateKey);
}

/** Build and sign a generic ACP response. */
function buildResponse(
  to: string,
  correlationId: string | undefined,
  type: ACPMessage['type'],
  body: Record<string, unknown>,
): ACPMessage {
  const msg: ACPMessage = {
    acp: '1.0',
    id: newMessageId(),
    type,
    from: AGENT_DID,
    to,
    correlationId: correlationId ?? '',
    createdAt: nowISO(),
    body,
  };
  return signMessage(msg, privateKey);
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

// Parse JSON with a 1 MB limit.  This enforces MESSAGE_TOO_LARGE at the
// body-parser level (Express will return 413 automatically).
app.use(express.json({ limit: '1mb', type: ['application/acp+json', 'application/json'] }));

// ---- DID Document --------------------------------------------------------

app.get(`/${AGENT_NAME}/did.json`, (_req: Request, res: Response) => {
  const doc: DIDDocument = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: AGENT_DID,
    verificationMethod: [
      {
        id: `${AGENT_DID}#key-1`,
        type: 'Ed25519VerificationKey2020',
        controller: AGENT_DID,
        publicKeyMultibase,
      },
    ],
    authentication: ['#key-1'],
    assertionMethod: ['#key-1'],
    service: [
      {
        id: '#acp',
        type: 'AgentCommunicationProtocol',
        serviceEndpoint: `${BASE_URL}/${AGENT_NAME}/inbox`,
      },
    ],
  };
  res.json(doc);
});

// ---- Agent Card ----------------------------------------------------------

app.get(`/.well-known/acp/${AGENT_NAME}.json`, (_req: Request, res: Response) => {
  const card: AgentCard = {
    acp: '1.0',
    name: AGENT_NAME,
    did: AGENT_DID,
    inbox: `${BASE_URL}/${AGENT_NAME}/inbox`,
    publicKey: publicKeyMultibase,
    description:
      'Echo agent -- returns whatever you send it. For testing ACP message flow.',
    capabilities: [
      {
        name: 'echo',
        description:
          'Echoes back the message body. Useful for testing signing, verification, and message flow.',
        schema: { type: 'object' },
        responseSchema: { type: 'object' },
      },
    ],
    auth: {
      required: true,
      methods: ['did-signature'],
      openAccess: true,
      allowlist: [],
      denylist: [],
    },
    rateLimit: { requests: 100, window: '60s' },
    contact: `admin@${DOMAIN}`,
  };
  res.json(card);
});

// ---- agents.txt ----------------------------------------------------------

app.get('/agents.txt', (_req: Request, res: Response) => {
  res.type('text/plain').send(
    `# ACP agents for this domain\nacp-version: 1.0\nacp-index: ${BASE_URL}/.well-known/acp/index.json\nacp-docs: https://github.com/clerkboard/acp/blob/main/spec/acp-rfc.md#appendix-e-implementers-quick-reference\n`,
  );
});

// ---- Agent Index ---------------------------------------------------------

app.get('/.well-known/acp/index.json', (_req: Request, res: Response) => {
  const index: AgentIndex = {
    domain: DOMAIN,
    protocol: 'acp/1.0',
    agents: [
      {
        name: AGENT_NAME,
        url: `/.well-known/acp/${AGENT_NAME}.json`,
        summary: 'Echo agent for testing',
        tags: ['echo', 'testing'],
      },
    ],
    pagination: { hasMore: false, total: 1 },
  };
  res.json(index);
});

// ---- Message Inbox -------------------------------------------------------

app.post(`/${AGENT_NAME}/inbox`, async (req: Request, res: Response) => {
  try {
    // 1. Content-Type check
    const ct = req.headers['content-type'] ?? '';
    if (!ct.includes('application/acp+json') && !ct.includes('application/json')) {
      res.status(415).json(
        errorResponse('unknown', undefined, 'SCHEMA_INVALID',
          'Content-Type must be application/acp+json or application/json', false),
      );
      return;
    }

    const msg = req.body as ACPMessage;

    // 2. Required envelope fields
    const required: (keyof ACPMessage)[] = ['acp', 'id', 'type', 'from', 'to', 'createdAt', 'body', 'signature'];
    for (const field of required) {
      if (msg[field] === undefined || msg[field] === null) {
        res.status(400).json(
          errorResponse(msg.from ?? 'unknown', msg.id, 'SCHEMA_INVALID',
            `Missing required field: ${field}`, false),
        );
        return;
      }
    }

    // 3. Check expiration
    if (msg.expiresAt) {
      if (new Date(msg.expiresAt).getTime() < Date.now()) {
        res.status(400).json(
          errorResponse(msg.from, msg.id, 'MESSAGE_EXPIRED',
            'Message has expired (expiresAt is in the past)', false),
        );
        return;
      }
    } else {
      // No expiresAt -- reject if createdAt is older than 24 hours
      const age = Date.now() - new Date(msg.createdAt).getTime();
      if (age > MAX_MESSAGE_AGE_MS) {
        res.status(400).json(
          errorResponse(msg.from, msg.id, 'MESSAGE_EXPIRED',
            'Message is older than 24 hours and has no expiresAt', false),
        );
        return;
      }
    }

    // 4. Idempotency -- reject duplicate message IDs
    if (idempotencyStore.hasMessage(msg.id)) {
      res.status(409).json(
        errorResponse(msg.from, msg.id, 'SCHEMA_INVALID',
          `Duplicate message ID: ${msg.id}`, false),
      );
      return;
    }
    // NOTE: Do NOT record the ID here. Record it only AFTER signature
    // verification succeeds, otherwise an attacker can poison the
    // idempotency store with forged messages to block legitimate ones.

    // 5. Resolve sender's public key
    let senderKeyMultibase: string | undefined;

    if (pinStore.hasPin(msg.from)) {
      // Known sender -- use pinned key
      const pin = pinStore.getPin(msg.from)!;
      senderKeyMultibase = pin.publicKeyMultibase;
    } else if (msg.type === 'negotiate' && typeof (msg.body as Record<string, unknown>).publicKey === 'string') {
      // First contact -- accept key from negotiate body
      senderKeyMultibase = (msg.body as Record<string, unknown>).publicKey as string;
    } else if (msg.type !== 'negotiate') {
      // Not pinned and not a negotiate -- reject
      res.status(403).json(
        errorResponse(msg.from, msg.id, 'FIRST_CONTACT_REQUIRED',
          'Send a negotiate message with firstContact: true before making requests', true),
      );
      return;
    }

    if (!senderKeyMultibase) {
      res.status(400).json(
        errorResponse(msg.from, msg.id, 'AUTH_FAILED',
          'Unable to resolve sender public key', false),
      );
      return;
    }

    // 6. Verify signature
    let senderPubKey: ReturnType<typeof importPublicKey>;
    try {
      senderPubKey = importPublicKey(senderKeyMultibase);
    } catch (err) {
      res.status(400).json(
        errorResponse(msg.from, msg.id, 'AUTH_FAILED',
          `Invalid sender public key: ${(err as Error).message}`, false),
      );
      return;
    }

    if (!verifyMessage(msg, senderPubKey)) {
      res.status(403).json(
        errorResponse(msg.from, msg.id, 'AUTH_FAILED',
          'Signature verification failed', false),
      );
      return;
    }

    // 7. Key pinning -- TOFU
    if (pinStore.hasPin(msg.from)) {
      const pin = pinStore.getPin(msg.from)!;
      if (pin.publicKeyMultibase !== senderKeyMultibase) {
        res.status(403).json(
          errorResponse(msg.from, msg.id, 'KEY_MISMATCH',
            'Sender public key does not match pinned key', false),
        );
        return;
      }
    } else {
      // First contact -- pin the key
      pinStore.setPin(msg.from, senderKeyMultibase);
      log.info('Pinned new sender key', { did: msg.from });
    }

    // 7b. Record message ID now that signature is verified
    idempotencyStore.addMessage(msg.id);

    // 7c. Validate contentRef objects in body (ACP v0.3)
    const contentRefError = validateContentRefs(msg.body);
    if (contentRefError) {
      res.status(400).json(
        errorResponse(msg.from, msg.id, 'SCHEMA_INVALID', contentRefError, false),
      );
      return;
    }

    // 8. Process message type
    log.info('Processing message', { id: msg.id, type: msg.type, from: msg.from });

    let response: ACPMessage;

    switch (msg.type) {
      case 'negotiate': {
        response = buildResponse(msg.from, msg.id, 'acknowledge', {
          accepted: true,
          message: 'First contact acknowledged. Key pinned.',
        });
        break;
      }

      case 'request': {
        if (msg.capability === 'echo') {
          response = buildResponse(msg.from, msg.id, 'response', {
            echo: msg.body,
            receivedAt: nowISO(),
          });
        } else {
          response = errorResponse(msg.from, msg.id, 'CAPABILITY_UNKNOWN',
            `Unknown capability: ${msg.capability ?? '(none)'}`, false);
        }
        break;
      }

      case 'cancel': {
        response = buildResponse(msg.from, msg.id, 'acknowledge', {
          cancelled: true,
        });
        break;
      }

      default: {
        response = buildResponse(msg.from, msg.id, 'acknowledge', {
          received: true,
        });
        break;
      }
    }

    res.status(200).json(response);
  } catch (err) {
    log.error('Unhandled error in inbox handler', {
      error: (err as Error).message,
      stack: (err as Error).stack,
    });
    res.status(500).json(
      errorResponse('unknown', undefined, 'INTERNAL_ERROR',
        'An unexpected error occurred', true),
    );
  }
});

// ---- Handle body-parser 413 errors --------------------------------------

app.use((err: Error & { status?: number; type?: string }, _req: Request, res: Response, _next: express.NextFunction) => {
  if (err.status === 413 || err.type === 'entity.too.large') {
    res.status(413).json(
      errorResponse('unknown', undefined, 'MESSAGE_TOO_LARGE',
        'Message exceeds 1 MB size limit', false),
    );
    return;
  }
  log.error('Unhandled express error', { error: err.message });
  res.status(500).json(
    errorResponse('unknown', undefined, 'INTERNAL_ERROR',
      'An unexpected error occurred', true),
  );
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, () => {
  log.info('ACP server started', {
    agent: AGENT_NAME,
    did: AGENT_DID,
    inbox: `${BASE_URL}/${AGENT_NAME}/inbox`,
    port: PORT,
  });

  // Human-friendly startup banner
  const banner = [
    '',
    '  ┌──────────────────────────────────────────────┐',
    '  │  ACP Reference Server                        │',
    '  ├──────────────────────────────────────────────┤',
    `  │  Agent : ${AGENT_NAME.padEnd(37)}│`,
    `  │  DID   : ${AGENT_DID.padEnd(37)}│`,
    `  │  Inbox : ${(`${BASE_URL}/${AGENT_NAME}/inbox`).padEnd(37)}│`,
    `  │  Port  : ${String(PORT).padEnd(37)}│`,
    '  └──────────────────────────────────────────────┘',
    '',
  ].join('\n');
  process.stdout.write(banner);
});

export { app };
