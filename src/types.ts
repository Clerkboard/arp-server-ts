/**
 * ACP (Agent Communication Protocol) TypeScript type definitions.
 */

// ---------------------------------------------------------------------------
// Message envelope
// ---------------------------------------------------------------------------

export type MessageType =
  | 'request'
  | 'response'
  | 'negotiate'
  | 'acknowledge'
  | 'error'
  | 'cancel';

export interface ACPMessage {
  acp: string;
  id: string;
  type: MessageType;
  from: string;
  to: string;
  capability?: string;
  correlationId?: string;
  createdAt: string;
  expiresAt?: string;
  body: Record<string, unknown>;
  signature?: string;
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export type ACPErrorCode =
  | 'AUTH_FAILED'
  | 'AUTH_DENIED'
  | 'FIRST_CONTACT_REQUIRED'
  | 'CAPABILITY_UNAVAILABLE'
  | 'CAPABILITY_UNKNOWN'
  | 'SCHEMA_INVALID'
  | 'RATE_LIMITED'
  | 'TASK_CANCELLED'
  | 'MESSAGE_EXPIRED'
  | 'MESSAGE_TOO_LARGE'
  | 'KEY_MISMATCH'
  | 'INTERNAL_ERROR';

export interface ACPErrorBody {
  code: ACPErrorCode;
  message: string;
  retryable: boolean;
}

// ---------------------------------------------------------------------------
// Agent Card & discovery
// ---------------------------------------------------------------------------

export interface Capability {
  name: string;
  description: string;
  schema: Record<string, unknown>;
  responseSchema: Record<string, unknown>;
}

export interface AgentCard {
  acp: string;
  name: string;
  did: string;
  inbox: string;
  publicKey: string;
  description: string;
  capabilities: Capability[];
  auth: {
    required: boolean;
    methods: string[];
    openAccess: boolean;
    allowlist: string[];
    denylist: string[];
  };
  rateLimit: {
    requests: number;
    window: string;
  };
  contact: string;
}

export interface AgentIndexEntry {
  name: string;
  url: string;
  summary: string;
}

export interface AgentIndex {
  domain: string;
  protocol: string;
  agents: AgentIndexEntry[];
  pagination: {
    hasMore: boolean;
    total: number;
  };
}

// ---------------------------------------------------------------------------
// DID Document
// ---------------------------------------------------------------------------

export interface DIDVerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyMultibase: string;
}

export interface DIDService {
  id: string;
  type: string;
  serviceEndpoint: string;
}

export interface DIDDocument {
  '@context': string;
  id: string;
  verificationMethod: DIDVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  service: DIDService[];
}

// ---------------------------------------------------------------------------
// Key pin store
// ---------------------------------------------------------------------------

export interface KeyPin {
  publicKeyMultibase: string;
  firstContact: string;
}

export interface KeyPinStore {
  [did: string]: KeyPin;
}

// ---------------------------------------------------------------------------
// Stored key pair
// ---------------------------------------------------------------------------

export interface StoredKeys {
  privateKeyPem: string;
  publicKeyMultibase: string;
}
