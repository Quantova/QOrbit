// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

export type Regime = 'leo' | 'meo' | 'geo' | 'heo' | 'other';
export type Maneuver = 'raising' | 'lowering' | 'stationkeeping' | 'avoidance' | 'deorbit';
export type Disposal = 'reentry' | 'graveyard' | 'retrieval';
export type RecordType = 'register' | 'launch' | 'maneuver' | 'transfer' | 'deorbit';

export interface KeyDescription {
  format: 'qorbit-key/1';
  algorithm: 'ML-DSA-65';
  id: string;
  publicKey: string;
}

export type Party = string | Uint8Array | KeyDescription;

export interface Signer {
  id: string;
  publicKey: string;
}

export interface Envelope<T = Record<string, unknown>> {
  format: 'qorbit/1';
  type: RecordType;
  algorithm: 'ML-DSA-65';
  signer: Signer;
  statement: T;
  signature: string;
  anchor?: unknown;
}

export interface RegisterOptions {
  key: Uint8Array;
  objectName: string;
  cosparId: string;
  regime: Regime;
  operatorLabel?: string;
  registeredAt?: string;
  note?: string;
}

export interface LaunchOptions {
  key: Uint8Array;
  register: Envelope;
  noradId: string;
  launchSite: string;
  authorityLabel?: string;
  launchedAt?: string;
  note?: string;
}

export interface ManeuverOptions {
  key: Uint8Array;
  record: Envelope;
  maneuverKind: Maneuver;
  controllerLabel?: string;
  maneuveredAt?: string;
  note?: string;
}

export interface TransferOptions {
  key: Uint8Array;
  record: Envelope;
  to: Party;
  toLabel?: string;
  transferredAt?: string;
  note?: string;
}

export interface DeorbitOptions {
  key: Uint8Array;
  record: Envelope;
  disposal: Disposal;
  holderLabel?: string;
  deorbitedAt?: string;
  note?: string;
}

export interface AnchorOptions {
  seed?: Uint8Array;
  index?: number;
  network?: string;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
  maxFee?: string | number | bigint;
  meter?: string | number | bigint;
  timeoutMs?: number;
  onPending?: (pending: unknown) => void;
  signal?: AbortSignal;
}

export interface VerifyOptions {
  type?: RecordType;
  prior?: Envelope;
  orbitId?: string;
  signerKeyId?: string;
  signerPublicKey?: string | Uint8Array;
  network: string;
  strict?: boolean;
  requireAnchor?: boolean;
  maxAnchorDelay?: number;
  at?: string;
  deadlineMs?: number;
  rpc?: string;
  clients?: unknown[];
  trustSingleEndpoint?: boolean;
  trustCustomEndpoints?: boolean;
  allowLoopback?: boolean;
}

export interface Check {
  name: string;
  ok: boolean;
  detail: string;
  transport: boolean;
  indeterminate: boolean;
  unproven: boolean;
}

export interface VerifyResult {
  valid: boolean;
  status: 'valid' | 'unproven' | 'indeterminate' | 'invalid';
  type: RecordType | null;
  orbitId?: string;
  signerId?: string;
  statement?: Record<string, unknown>;
  anchoredAt?: string | null;
  endpoints: string[];
  officialEndpoints: boolean | null;
  checks: Check[];
}

export function generateKey(): Uint8Array;
export function publicKey(key: Uint8Array): Uint8Array;
export function keyId(key: Uint8Array): string;
export function describeKey(key: Uint8Array): KeyDescription;
export function objectRef(secret: Uint8Array, reference: string): string;
export function register(options: RegisterOptions): Envelope;
export function launch(options: LaunchOptions): Envelope;
export function maneuver(options: ManeuverOptions): Envelope;
export function transfer(options: TransferOptions): Envelope;
export function deorbit(options: DeorbitOptions): Envelope;
export function anchor(envelopes: Envelope | Envelope[], options: AnchorOptions): Promise<Envelope[]>;
export function complete(envelopes: Envelope | Envelope[], pending: unknown, options?: AnchorOptions): Promise<Envelope[]>;
export function verify(envelope: Envelope, options: VerifyOptions): Promise<VerifyResult>;
export function anchorDigest(envelope: Envelope): string;
export function recordRef(envelope: Envelope): string;

export const FORMAT: 'qorbit/1';
export const ALGORITHM: 'ML-DSA-65';
export const KIND: 1407;
export const TYPES: readonly RecordType[];
export const REGIMES: readonly Regime[];
export const MANEUVERS: readonly Maneuver[];
export const DISPOSALS: readonly Disposal[];
export const PUBLIC_KEY_BYTES: 1952;
export const SIGNATURE_BYTES: 3309;
