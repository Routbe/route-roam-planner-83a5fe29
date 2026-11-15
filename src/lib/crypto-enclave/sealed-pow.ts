/**
 * Hashcash proof-of-work for sealed bookings and profile-card requests (BLAKE3).
 *
 *   payloadHash = BLAKE3(envelope bytes)                       (stored as blake3_payload_hash)
 *   binding     = BLAKE3("rout.sealed.binding.v1" || purpose || pid(16) ||
 *                        for each copy, sorted by ref: ref(16) || payloadHash(32))
 *   digest      = BLAKE3("rout.pow.sealed.v1" || binding || epoch(u32 BE) || nonce(8))
 *   valid       = digest starts with `bits` zero bits
 *
 * Stateless: no server challenge. The nonce is bound to the exact ciphertext
 * and to a 10-minute epoch bucket; the server checks it before any database
 * call, and the database refuses a second row with the same payload hash, so a
 * solved nonce cannot be replayed. The visitor solves it in the crypto worker.
 * Browser-safe: no server imports, no secrets.
 */
import { blake3 } from "@noble/hashes/blake3.js";

export type SealedPowPurpose = "booking" | "inquiry";
export const SEALED_POW_DEFAULT_BITS = 16;
export const SEALED_POW_MIN_BITS = 12;
export const SEALED_POW_MAX_BITS = 24;
export const SEALED_EPOCH_SECONDS = 600;
/** Buckets accepted on either side of the verifier's own bucket (clock skew, slow devices). */
export const SEALED_EPOCH_SLACK = 1;
export const SEALED_NONCE_BYTES = 8;
export const SEALED_NONCE_HEX = /^[0-9a-f]{16}$/;

const enc = new TextEncoder();
const BIND_LABEL = enc.encode("rout.sealed.binding.v1");
const POW_LABEL = enc.encode("rout.pow.sealed.v1");
const PURPOSE: Record<SealedPowPurpose, number> = { booking: 1, inquiry: 2 };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export class SealedPowError extends Error {
  constructor(code: "pow_input") {
    super(code);
    this.name = "SealedPowError";
  }
}

export const epochBucketAt = (ms: number): number => Math.floor(ms / 1000 / SEALED_EPOCH_SECONDS);
export const isEpochFresh = (epoch: number, nowMs: number): boolean =>
  Number.isInteger(epoch) && Math.abs(epoch - epochBucketAt(nowMs)) <= SEALED_EPOCH_SLACK;
export const isSealedPowBits = (bits: unknown): bits is number =>
  typeof bits === "number" && Number.isInteger(bits) && bits >= SEALED_POW_MIN_BITS && bits <= SEALED_POW_MAX_BITS;

export const payloadHash = (envelope: Uint8Array): Uint8Array => blake3(envelope);

function uuidBytes(id: string): Uint8Array {
  if (!UUID.test(id)) throw new SealedPowError("pow_input");
  const hex = id.replace(/-/g, "");
  return Uint8Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}

export type SealedCopyHash = { ref: string; hash: Uint8Array };

/** Binds the proof to the purpose, the payload id and every host copy (order-independent). */
export function sealedBinding(purpose: SealedPowPurpose, pid: string, copies: readonly SealedCopyHash[]): Uint8Array {
  if (copies.length < 1 || copies.length > 8) throw new SealedPowError("pow_input");
  const sorted = [...copies].sort((a, b) => (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
  if (new Set(sorted.map((c) => c.ref)).size !== sorted.length) throw new SealedPowError("pow_input");
  const parts = [BIND_LABEL, Uint8Array.of(PURPOSE[purpose]), uuidBytes(pid)];
  for (const c of sorted) {
    if (c.hash.length !== 32) throw new SealedPowError("pow_input");
    parts.push(uuidBytes(c.ref), c.hash);
  }
  const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    buf.set(p, at);
    at += p.length;
  }
  return blake3(buf);
}

function preimage(binding: Uint8Array, epoch: number): Uint8Array {
  if (binding.length !== 32 || !Number.isInteger(epoch) || epoch < 0 || epoch > 0xffffffff) throw new SealedPowError("pow_input");
  const buf = new Uint8Array(POW_LABEL.length + 32 + 4 + SEALED_NONCE_BYTES);
  buf.set(POW_LABEL);
  buf.set(binding, POW_LABEL.length);
  new DataView(buf.buffer).setUint32(POW_LABEL.length + 32, epoch, false);
  return buf;
}

export function leadingZeroBits(digest: Uint8Array): number {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

const hexOf = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string) => Uint8Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(i * 2, i * 2 + 2), 16));

export function sealedPowDigest(binding: Uint8Array, epoch: number, nonceHex: string): Uint8Array {
  if (!SEALED_NONCE_HEX.test(nonceHex)) throw new SealedPowError("pow_input");
  const buf = preimage(binding, epoch);
  buf.set(fromHex(nonceHex), buf.length - SEALED_NONCE_BYTES);
  return blake3(buf);
}

export function verifySealedPow(binding: Uint8Array, epoch: number, nonceHex: string, bits: number): boolean {
  if (!isSealedPowBits(bits)) return false;
  try {
    return leadingZeroBits(sealedPowDigest(binding, epoch, nonceHex)) >= bits;
  } catch {
    return false;
  }
}

/** Tries `count` nonces from `startAt`; the worker loops over batches and yields between them. */
export function searchSealedPow(binding: Uint8Array, epoch: number, bits: number, startAt: number, count: number): string | null {
  if (!isSealedPowBits(bits)) throw new SealedPowError("pow_input");
  const buf = preimage(binding, epoch);
  const view = new DataView(buf.buffer, buf.length - SEALED_NONCE_BYTES, SEALED_NONCE_BYTES);
  const high = crypto.getRandomValues(new Uint32Array(1))[0] ?? 0;
  view.setUint32(0, high, false);
  for (let i = 0, counter = startAt >>> 0; i < count; i++, counter = (counter + 1) >>> 0) {
    view.setUint32(4, counter, false);
    if (leadingZeroBits(blake3(buf)) >= bits) return hexOf(buf.subarray(buf.length - SEALED_NONCE_BYTES));
  }
  return null;
}
