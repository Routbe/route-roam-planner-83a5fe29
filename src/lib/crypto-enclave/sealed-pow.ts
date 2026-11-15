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
  try {
    return blake3(buf);
  } finally {
    buf.fill(0);
  }
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
  try {
    buf.set(fromHex(nonceHex), buf.length - SEALED_NONCE_BYTES);
    return blake3(buf);
  } finally {
    buf.fill(0);
  }
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
  const high = crypto.getRandomValues(new Uint32Array(1));
  view.setUint32(0, high[0] ?? 0, false);
  high.fill(0);
  try {
    for (let i = 0, counter = startAt >>> 0; i < count; i++, counter = (counter + 1) >>> 0) {
      view.setUint32(4, counter, false);
      const digest = blake3(buf);
      const hit = leadingZeroBits(digest) >= bits;
      digest.fill(0);
      if (hit) return hexOf(buf.subarray(buf.length - SEALED_NONCE_BYTES));
    }
    return null;
  } finally {
    buf.fill(0);
  }
}

/** Difficulty the server demands; the client solves at the same level. */
export const SEALED_POW_REQUIRED_BITS = SEALED_POW_DEFAULT_BITS;
/** Upper bound on nonces the worker tries (2^24: ~256x the expected work at 16 bits). */
export const SEALED_POW_MAX_TRIES = 1 << 24;

export type SealedPowProof = { nonce: string; epoch: number };
export type SealedCopyBytes = { ref: string; envelope: Uint8Array };

/** Solves the proof for the given copies in batches (crypto worker only); every temporary is wiped. */
export function solveSealedPow(purpose: SealedPowPurpose, pid: string, copies: readonly SealedCopyBytes[], nowMs: number, bits = SEALED_POW_REQUIRED_BITS): SealedPowProof {
  const hashes = copies.map((c) => ({ ref: c.ref, hash: payloadHash(c.envelope) }));
  let binding: Uint8Array | null = null;
  try {
    binding = sealedBinding(purpose, pid, hashes);
    const epoch = epochBucketAt(nowMs);
    const batch = 4096;
    for (let start = 0; start < SEALED_POW_MAX_TRIES; start += batch) {
      const nonce = searchSealedPow(binding, epoch, bits, start, batch);
      if (nonce) return { nonce, epoch };
    }
    throw new SealedPowError("pow_input");
  } finally {
    binding?.fill(0);
    for (const h of hashes) h.hash.fill(0);
  }
}

export type SealedPowCheck =
  | { ok: true; hashes: Map<string, Uint8Array> }
  | { ok: false; reason: "pow_invalid" | "pow_stale" };

/**
 * Server pre-validation, before any database call: the epoch is within one bucket of the
 * server clock and the nonce meets SEALED_POW_REQUIRED_BITS over the exact ciphertext bytes.
 * Returns the BLAKE3 payload hashes the database stores (unique: a replay is refused there).
 */
export function checkSealedPow(purpose: SealedPowPurpose, pid: string, copies: readonly SealedCopyBytes[], proof: SealedPowProof, nowMs: number): SealedPowCheck {
  if (!SEALED_NONCE_HEX.test(proof.nonce) || !Number.isInteger(proof.epoch) || proof.epoch <= 0) return { ok: false, reason: "pow_invalid" };
  if (!isEpochFresh(proof.epoch, nowMs)) return { ok: false, reason: "pow_stale" };
  const hashes = new Map<string, Uint8Array>();
  let binding: Uint8Array | null = null;
  try {
    for (const c of copies) hashes.set(c.ref, payloadHash(c.envelope));
    binding = sealedBinding(purpose, pid, [...hashes].map(([ref, hash]) => ({ ref, hash })));
    if (!verifySealedPow(binding, proof.epoch, proof.nonce, SEALED_POW_REQUIRED_BITS)) return { ok: false, reason: "pow_invalid" };
    return { ok: true, hashes };
  } catch {
    return { ok: false, reason: "pow_invalid" };
  } finally {
    binding?.fill(0);
  }
}
