/**
 * ARP (Agent Relations Protocol) TypeScript type definitions.
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
  | 'cancel'
  | 'notify'; // v0.7 — Notifications (Section 21)

export interface ARPMessage {
  arp: string;
  id: string;
  type: MessageType;
  from: string;
  to: string;
  capability?: string;
  event?: string; // v0.7 — present on `notify` messages
  notificationId?: string; // v0.7 — present on `notify` messages
  correlationId?: string;
  createdAt: string;
  expiresAt?: string;
  body: Record<string, unknown>;
  signature?: string;
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export type ARPErrorCode =
  | 'AUTH_FAILED'
  | 'AUTH_DENIED'
  | 'FIRST_CONTACT_REQUIRED'
  | 'CAPABILITY_DENIED'
  | 'CAPABILITY_UNAVAILABLE'
  | 'CAPABILITY_UNKNOWN'
  | 'SCHEMA_INVALID'
  | 'RATE_LIMITED'
  | 'TASK_CANCELLED'
  | 'MESSAGE_EXPIRED'
  | 'MESSAGE_TOO_LARGE'
  | 'KEY_MISMATCH'
  | 'INTERNAL_ERROR'
  // v0.7 — Notifications (Section 21)
  | 'NOTIFICATION_REJECTED'
  // v0.7 — Settlements (Section 22)
  | 'SETTLEMENT_REQUIRED'
  | 'QUOTE_EXPIRED'
  | 'QUOTE_INVALID';

export interface ARPErrorBody {
  code: ARPErrorCode;
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
  open?: boolean;
}

export interface AgentCard {
  '@context'?: Record<string, string>;
  '@type'?: string;
  arp: string;
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
  // v0.7 — Notifications (Section 21.6)
  notifications?: NotificationsDeclaration;
  // v0.7 — Settlements (Section 22.3)
  settlements?: SettlementsDeclaration;
}

export interface AgentIndexEntry {
  name: string;
  url: string;
  summary: string;
  tags?: string[];
}

export interface AgentIndex {
  '@context'?: Record<string, string>;
  '@type'?: string;
  domain: string;
  protocol: string;
  agents: AgentIndexEntry[];
  pagination: {
    hasMore: boolean;
    total: number;
  };
}

// ---------------------------------------------------------------------------
// Relations (v0.4.0)
// ---------------------------------------------------------------------------

export type RelationStatus = 'pending' | 'active' | 'dormant' | 'terminated';

export type TrustLevel = 'trusted' | 'known' | 'new' | 'unknown';

export interface Relation {
  peerDid: string;
  pinnedKey: string;
  status: RelationStatus;
  firstContact: string;
  lastActivity: string;
  completions: number;
  // v0.7 — Notifications (Section 21.3)
  acceptNotifications?: NotificationPermission;
}

// ---------------------------------------------------------------------------
// Notifications (v0.7, Section 21)
// ---------------------------------------------------------------------------

export interface NotificationsDeclaration {
  supported: boolean;
  events?: Record<string, string>;
  defaultLease?: number;
  maxLease?: number;
}

export interface NotificationPermission {
  events: string[];
  validUntil: string;
}

// ---------------------------------------------------------------------------
// Settlements (v0.7, Section 22)
// ---------------------------------------------------------------------------

export type SettlementPrimitive = 'prepay' | 'postpay';

export interface SettlementRail {
  name: string;
  spec: string;
  currencies: string[];
}

export interface SettlementsDeclaration {
  supported: boolean;
  rails: SettlementRail[];
  primitives: SettlementPrimitive[];
  settlementWindow?: string;
  quoteCapability?: string;
}

export interface SettlementQuoteRail {
  name: string;
  target: string;
}

export interface SettlementQuote {
  seller: string; // v0.7.1 — DID of the quote issuer
  buyer: string; // v0.7.1 — DID of the only agent that may settle
  taskRef: string; // v0.7.1 — correlationId of the task being priced
  keyRef: string; // v0.7.1 — verification method ID of the signing key
  amount: string;
  currency: string;
  primitive: SettlementPrimitive;
  validUntil: string;
  quoteId: string;
  rails: SettlementQuoteRail[];
  memo?: string;
  quoteSig: string;
}

export interface Settlement {
  amount: string;
  currency: string;
  primitive: SettlementPrimitive;
  rail: string;
  quoteId: string;
  railRef: string;
  settledAt: string;
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
// Relation store (replaces key pin store in v0.4.0)
// ---------------------------------------------------------------------------

export interface RelationStore {
  [did: string]: Relation;
}

// ---------------------------------------------------------------------------
// Stored key pair
// ---------------------------------------------------------------------------

export interface StoredKeys {
  privateKeyPem: string;
  publicKeyMultibase: string;
}
