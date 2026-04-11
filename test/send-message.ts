/**
 * ACP end-to-end test script.
 *
 * 1. Generate a temporary Ed25519 key pair for a test sender.
 * 2. Send a first-contact negotiate message (signed).
 * 3. Verify the acknowledge response.
 * 4. Send an echo request (signed).
 * 5. Verify the echo response signature and body.
 *
 * Usage:  tsx test/send-message.ts
 */

import crypto from 'node:crypto';
import bs58 from 'bs58';
import _canonicalize from 'canonicalize';
const canonicalize = _canonicalize as unknown as (obj: unknown) => string | undefined;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = Number(process.env.ACP_PORT ?? 3141);
const DOMAIN = process.env.ACP_DOMAIN ?? 'localhost';
const AGENT_NAME = process.env.ACP_AGENT_NAME ?? 'echo';
const BASE_URL = `http://${DOMAIN}:${PORT}`;
const INBOX_URL = `${BASE_URL}/${AGENT_NAME}/inbox`;
const SENDER_DID = `did:web:${DOMAIN}:test-sender`;
const RECEIVER_DID = `did:web:${DOMAIN}:${AGENT_NAME}`;

// ---------------------------------------------------------------------------
// Crypto helpers (mirrors src/crypto.ts but standalone for testing)
// ---------------------------------------------------------------------------

const ED25519_SPKI_HEADER = Buffer.from('302a300506032b6570032100', 'hex');

function rawPublicKey(pub: crypto.KeyObject): Buffer {
  const spki = pub.export({ type: 'spki', format: 'der' }) as Buffer;
  return spki.subarray(spki.length - 32);
}

function encodeMultibase(raw: Buffer): string {
  return 'z' + bs58.encode(raw);
}

function decodeMultibase(mb: string): Buffer {
  return Buffer.from(bs58.decode(mb.slice(1)));
}

function importPublicKey(mb: string): crypto.KeyObject {
  const raw = decodeMultibase(mb);
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_HEADER, raw]),
    format: 'der',
    type: 'spki',
  });
}

interface ACPMessage {
  acp: string;
  id: string;
  type: string;
  from: string;
  to: string;
  capability?: string;
  correlationId?: string;
  createdAt: string;
  expiresAt?: string;
  body: Record<string, unknown>;
  signature?: string;
}

function signMessage(msg: ACPMessage, priv: crypto.KeyObject): ACPMessage {
  const { signature: _s, ...rest } = msg;
  const payload = Buffer.from(canonicalize(rest)!, 'utf-8');
  const sig = crypto.sign(null, payload, priv);
  msg.signature = encodeMultibase(sig);
  return msg;
}

function verifyMessage(msg: ACPMessage, pub: crypto.KeyObject): boolean {
  if (!msg.signature) return false;
  const sigBytes = decodeMultibase(msg.signature);
  const { signature: _s, ...rest } = msg;
  const payload = Buffer.from(canonicalize(rest)!, 'utf-8');
  return crypto.verify(null, payload, pub, sigBytes);
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function assert(label: string, condition: boolean, detail?: string): void {
  if (condition) {
    passed++;
    process.stdout.write(`  PASS  ${label}\n`);
  } else {
    failed++;
    process.stderr.write(`  FAIL  ${label}${detail ? ` -- ${detail}` : ''}\n`);
  }
}

async function sendACP(msg: ACPMessage): Promise<{ status: number; body: ACPMessage }> {
  const res = await fetch(INBOX_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/acp+json' },
    body: JSON.stringify(msg),
  });
  const body = (await res.json()) as ACPMessage;
  return { status: res.status, body };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  process.stdout.write('\n  ACP Test Suite\n  ──────────────\n\n');

  // Generate ephemeral test key pair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const senderKeyMultibase = encodeMultibase(rawPublicKey(publicKey));

  // Fetch the server's agent card to get its public key
  process.stdout.write('  Fetching agent card...\n');
  const cardRes = await fetch(`${BASE_URL}/.well-known/acp/${AGENT_NAME}.json`);
  const card = (await cardRes.json()) as { publicKey: string };
  const serverPub = importPublicKey(card.publicKey);
  assert('Agent card reachable', cardRes.status === 200);

  // Fetch DID document
  const didRes = await fetch(`${BASE_URL}/${AGENT_NAME}/did.json`);
  const didDoc = (await didRes.json()) as Record<string, unknown>;
  assert('DID document reachable', didRes.status === 200);
  assert('DID document has correct id', (didDoc as { id: string }).id === RECEIVER_DID);

  // Fetch agent index
  const indexRes = await fetch(`${BASE_URL}/.well-known/acp/index.json`);
  assert('Agent index reachable', indexRes.status === 200);

  // ---- Test: request before negotiate should be rejected ----
  process.stdout.write('\n  -- Pre-negotiate request (should fail) --\n');
  {
    const msg: ACPMessage = {
      acp: '1.0',
      id: `msg_${crypto.randomUUID()}`,
      type: 'request',
      from: `did:web:${DOMAIN}:unknown-sender`,
      to: RECEIVER_DID,
      capability: 'echo',
      createdAt: new Date().toISOString(),
      body: { text: 'should fail' },
    };
    signMessage(msg, privateKey);
    const { status, body } = await sendACP(msg);
    assert('Pre-negotiate request rejected', status === 403);
    assert('Error code is FIRST_CONTACT_REQUIRED',
      (body.body as { code: string }).code === 'FIRST_CONTACT_REQUIRED');
  }

  // ---- Step 1: First-contact negotiate ----
  process.stdout.write('\n  -- First-contact negotiate --\n');
  let negotiateResp: ACPMessage;
  {
    const msg: ACPMessage = {
      acp: '1.0',
      id: `msg_${crypto.randomUUID()}`,
      type: 'negotiate',
      from: SENDER_DID,
      to: RECEIVER_DID,
      createdAt: new Date().toISOString(),
      body: {
        firstContact: true,
        publicKey: senderKeyMultibase,
      },
    };
    signMessage(msg, privateKey);
    const { status, body } = await sendACP(msg);
    negotiateResp = body;

    assert('Negotiate returns 200', status === 200);
    assert('Response type is acknowledge', body.type === 'acknowledge');
    assert('Response body.accepted is true', (body.body as { accepted: boolean }).accepted === true);
    assert('Response has valid signature', verifyMessage(body, serverPub));
    assert('Response correlationId matches', body.correlationId === msg.id);
  }

  // ---- Step 2: Echo request ----
  process.stdout.write('\n  -- Echo request --\n');
  {
    const payload = { text: 'Hello, ACP!', number: 42, nested: { key: 'value' } };
    const msg: ACPMessage = {
      acp: '1.0',
      id: `msg_${crypto.randomUUID()}`,
      type: 'request',
      from: SENDER_DID,
      to: RECEIVER_DID,
      capability: 'echo',
      createdAt: new Date().toISOString(),
      body: payload,
    };
    signMessage(msg, privateKey);
    const { status, body } = await sendACP(msg);

    assert('Echo returns 200', status === 200);
    assert('Response type is response', body.type === 'response');
    assert('Response has valid signature', verifyMessage(body, serverPub));
    assert('Echo body contains original payload',
      JSON.stringify((body.body as { echo: unknown }).echo) === JSON.stringify(payload));
    assert('Response correlationId matches', body.correlationId === msg.id);
  }

  // ---- Step 3: Unknown capability ----
  process.stdout.write('\n  -- Unknown capability --\n');
  {
    const msg: ACPMessage = {
      acp: '1.0',
      id: `msg_${crypto.randomUUID()}`,
      type: 'request',
      from: SENDER_DID,
      to: RECEIVER_DID,
      capability: 'nonexistent',
      createdAt: new Date().toISOString(),
      body: {},
    };
    signMessage(msg, privateKey);
    const { status, body } = await sendACP(msg);

    assert('Unknown capability returns 200', status === 200);
    assert('Response type is error', body.type === 'error');
    assert('Error code is CAPABILITY_UNKNOWN',
      (body.body as { code: string }).code === 'CAPABILITY_UNKNOWN');
  }

  // ---- Step 4: Duplicate message ID ----
  process.stdout.write('\n  -- Duplicate message ID --\n');
  {
    const dupeId = `msg_${crypto.randomUUID()}`;
    const msg1: ACPMessage = {
      acp: '1.0',
      id: dupeId,
      type: 'request',
      from: SENDER_DID,
      to: RECEIVER_DID,
      capability: 'echo',
      createdAt: new Date().toISOString(),
      body: { text: 'first' },
    };
    signMessage(msg1, privateKey);
    await sendACP(msg1);

    const msg2: ACPMessage = {
      acp: '1.0',
      id: dupeId,
      type: 'request',
      from: SENDER_DID,
      to: RECEIVER_DID,
      capability: 'echo',
      createdAt: new Date().toISOString(),
      body: { text: 'duplicate' },
    };
    signMessage(msg2, privateKey);
    const { status } = await sendACP(msg2);
    assert('Duplicate message ID returns 409', status === 409);
  }

  // ---- Step 5: Expired message ----
  process.stdout.write('\n  -- Expired message --\n');
  {
    const msg: ACPMessage = {
      acp: '1.0',
      id: `msg_${crypto.randomUUID()}`,
      type: 'request',
      from: SENDER_DID,
      to: RECEIVER_DID,
      capability: 'echo',
      createdAt: new Date().toISOString(),
      expiresAt: '2020-01-01T00:00:00Z',
      body: { text: 'expired' },
    };
    signMessage(msg, privateKey);
    const { status, body } = await sendACP(msg);
    assert('Expired message returns 400', status === 400);
    assert('Error code is MESSAGE_EXPIRED',
      (body.body as { code: string }).code === 'MESSAGE_EXPIRED');
  }

  // ---- Step 6: Cancel message ----
  process.stdout.write('\n  -- Cancel message --\n');
  {
    const msg: ACPMessage = {
      acp: '1.0',
      id: `msg_${crypto.randomUUID()}`,
      type: 'cancel',
      from: SENDER_DID,
      to: RECEIVER_DID,
      correlationId: 'task_some-old-task',
      createdAt: new Date().toISOString(),
      body: {},
    };
    signMessage(msg, privateKey);
    const { status, body } = await sendACP(msg);
    assert('Cancel returns 200', status === 200);
    assert('Cancel response type is acknowledge', body.type === 'acknowledge');
    assert('Cancel response body.cancelled is true',
      (body.body as { cancelled: boolean }).cancelled === true);
  }

  // ---- Summary ----
  process.stdout.write(`\n  ──────────────\n  ${passed} passed, ${failed} failed\n\n`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`\n  FATAL: ${(err as Error).message}\n`);
  process.stderr.write(`  Is the server running on ${INBOX_URL}?\n\n`);
  process.exit(1);
});
