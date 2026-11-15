/**
 * Wire format of end-to-end sealed guest details (booking engine, Fase 1).
 *
 * The guest's browser seals name, e-mail, note and intake answers in the crypto
 * worker (booking-seal.ts, RVE1 kind bkh: ML-KEM-1024 + X25519) once per host
 * of the event type. The server only checks the envelope headers and stores
 * `{ v: 2, pid, hosts }` in bookings.intake_answers; the plaintext columns get
 * fixed placeholders, so no guest name, address or note reaches Neon.
 *
 * Host keys: each host publishes `users/<uid>/booking-key.json` in the client
 * Scaleway bucket (public key + seed sealed under the workspace key). Guests
 * never learn host user ids: an envelope is bound to `hostRefOf(publicKey)`.
 *
 * Browser-safe: no server imports, no KEM code (that lives in the worker).
 */
import { z } from "zod";
import { sha256 } from "@noble/hashes/sha2.js";

export const SEALED_INTAKE_VERSION = 2;
/** Placeholder for bookings.guest_name (db/0218 demands 1..120 characters). */
export const SEALED_GUEST_NAME = "RVE1";
/** `.invalid` (RFC 2606) can never receive mail; db/0218 only demands 3..254 chars and an '@' after the first. */
const SEALED_DOMAIN = "sealed.invalid";
export const sealedGuestEmail = (payloadId: string) => `${payloadId}@${SEALED_DOMAIN}`;
export const isSealedGuestEmail = (email: unknown): boolean => typeof email === "string" && email.toLowerCase().endsWith(`@${SEALED_DOMAIN}`);

/** RVE1 header (pqc-envelope.ts): magic, suite 1, kind, holder, 16-byte recipient kid. */
const RVE1_MAGIC = [0x52, 0x56, 0x45, 0x31] as const;
const KIND_BKH = 5;
const HOLDER_MEMBER_DEVICE = 2;
const OFF_KID = 7;
const KID_LEN = 16;
const ENVELOPE_OVERHEAD = 1647 + 16;
/** booking-seal.ts BOOKING_PAD_BUCKETS: an envelope has one of exactly three sizes. */
export const HOST_ENVELOPE_SIZES = [1024, 4096, 16384].map((b) => b + ENVELOPE_OVERHEAD) as readonly number[];
/** Leaves room under the 64 KiB p_intake check of rout_booking_create. */
export const MAX_SEALED_INTAKE_BYTES = 60_000;
export const MAX_SEALED_HOSTS = 8;

const B64U = /^[A-Za-z0-9_-]+$/;
export const b64uEncode = (bytes: Uint8Array): string => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
/** Strict: only canonical unpadded base64url decodes. */
export function b64uDecode(text: string): Uint8Array | null {
  if (!B64U.test(text) || text.length % 4 === 1) return null;
  try {
    const raw = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
    const out = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    return b64uEncode(out) === text ? out : null;
  } catch {
    return null;
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HOST_REF_LABEL = new TextEncoder().encode("rout.booking.host-ref.v1");

/** Host reference for envelope contexts: a UUID derived from the host's booking public key, never the user id. */
export function hostRefOf(publicKey: Uint8Array): string {
  const input = new Uint8Array(HOST_REF_LABEL.length + publicKey.length);
  input.set(HOST_REF_LABEL);
  input.set(publicKey, HOST_REF_LABEL.length);
  const h = sha256(input).slice(0, 16);
  h[6] = (h[6]! & 0x0f) | 0x40;
  h[8] = (h[8]! & 0x3f) | 0x80;
  const hex = Array.from(h, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Published host booking key (Scaleway `users/<uid>/booking-key.json`). Only `publicKey` is ever shown to guests. */
export const hostBookingKeyDoc = z
  .object({
    v: z.literal(1),
    kid: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
    publicKey: z.string().regex(B64U).length(2134),
    /** AES-256-GCM `v1.iv.ct` under the workspace key (Master Key), AAD rout.booking.host-key.v1:<uid>:<kid>. */
    sealedSeed: z.string().regex(/^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{64}$/),
    keyId: z.string().min(1).max(200),
  })
  .strict();
export type HostBookingKeyDoc = z.infer<typeof hostBookingKeyDoc>;

/** What a guest receives per host: the reference and the public key, nothing else. */
export type PublicHostKey = { ref: string; publicKey: string };

/** Hashcash proof (crypto-enclave/sealed-pow.ts) over the exact envelopes; checked before any database call. */
export const sealedPowInput = z
  .object({ nonce: z.string().regex(/^[0-9a-f]{16}$/), epoch: z.number().int().positive().max(0xffffffff) })
  .strict();
export type SealedPowInput = z.infer<typeof sealedPowInput>;

/** db/0278 intake marker: the host copies live in public.booking_payloads, not in intake_answers. */
export const SEALED_INTAKE_V3 = 3;
export function parseSealedIntakeV3(stored: unknown): { pid: string } | null {
  if (typeof stored !== "object" || stored === null) return null;
  const o = stored as { v?: unknown; pid?: unknown };
  return o.v === SEALED_INTAKE_V3 && typeof o.pid === "string" && UUID.test(o.pid) && Object.keys(o).length === 2 ? { pid: o.pid } : null;
}

/** Sealed guest details as sent by the browser and stored in intake_answers. */
export const sealedGuestDetails = z
  .object({
    pid: z.string().regex(UUID),
    hosts: z.record(z.string().regex(UUID), z.string().max(Math.ceil((16384 + ENVELOPE_OVERHEAD) * 4 / 3) + 4)),
  })
  .strict()
  .refine((s) => {
    const n = Object.keys(s.hosts).length;
    return n >= 1 && n <= MAX_SEALED_HOSTS;
  }, "host_count");
export type SealedGuestDetails = z.infer<typeof sealedGuestDetails>;
export type SealedIntake = { v: 2 } & SealedGuestDetails;

/** Reads a stored intake value; null for legacy (v1) or anything malformed. */
export function parseSealedIntake(stored: unknown): SealedIntake | null {
  if (typeof stored !== "object" || stored === null || (stored as { v?: unknown }).v !== SEALED_INTAKE_VERSION) return null;
  const { v: _v, ...rest } = stored as Record<string, unknown>;
  const r = sealedGuestDetails.safeParse(rest);
  return r.success ? { v: 2, ...r.data } : null;
}

/**
 * Header check of one host copy, without any key: RVE1, suite 1, kind bkh,
 * holder member_device, the host's key id, and one of the three padded sizes.
 */
export function isHostEnvelopeFor(envelope: Uint8Array, kid: Uint8Array): boolean {
  if (kid.length !== KID_LEN || !HOST_ENVELOPE_SIZES.includes(envelope.length)) return false;
  for (let i = 0; i < 4; i++) if (envelope[i] !== RVE1_MAGIC[i]) return false;
  if (envelope[4] !== 1 || envelope[5] !== KIND_BKH || envelope[6] !== HOLDER_MEMBER_DEVICE) return false;
  for (let i = 0; i < KID_LEN; i++) if (envelope[OFF_KID + i] !== kid[i]) return false;
  return true;
}
