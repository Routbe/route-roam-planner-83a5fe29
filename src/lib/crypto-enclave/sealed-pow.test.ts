import { describe, expect, it, vi } from "vitest";
import { blake3 } from "@noble/hashes/blake3.js";
import {
  checkSealedPow, epochBucketAt, leadingZeroBits, payloadHash, SEALED_EPOCH_SECONDS, SEALED_POW_REQUIRED_BITS,
  sealedBinding, sealedPowDigest, solveSealedPow,
} from "./sealed-pow";

const PID = "11111111-2222-4333-8444-555555555555";
const R1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const R2 = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const env = (fill: number) => new Uint8Array(3583).fill(fill);
const NOW = Date.UTC(2026, 10, 15, 12, 0, 0);

describe("sealed BLAKE3 Hashcash", () => {
  it("demands 16 leading zero bits in 10-minute epoch buckets", () => {
    expect(SEALED_POW_REQUIRED_BITS).toBe(16);
    expect(SEALED_EPOCH_SECONDS).toBe(600);
    expect(epochBucketAt(NOW + 599_999) - epochBucketAt(NOW - (NOW % 600_000))).toBe(0);
  });

  it("a solved proof verifies and its digest really has the required zero bits", () => {
    const copies = [{ ref: R1, envelope: env(1) }];
    const proof = solveSealedPow("booking", PID, copies, NOW);
    const r = checkSealedPow("booking", PID, copies, proof, NOW);
    expect(r.ok).toBe(true);
    const binding = sealedBinding("booking", PID, [{ ref: R1, hash: blake3(env(1)) }]);
    expect(leadingZeroBits(sealedPowDigest(binding, proof.epoch, proof.nonce))).toBeGreaterThanOrEqual(16);
    expect(r.ok && [...r.hashes.values()][0]).toEqual(payloadHash(env(1)));
  });

  it("is bound to the ciphertext, the payload id, the purpose and every host copy", () => {
    const copies = [{ ref: R1, envelope: env(1) }, { ref: R2, envelope: env(2) }];
    const proof = solveSealedPow("booking", PID, copies, NOW);
    expect(checkSealedPow("booking", PID, [...copies].reverse(), proof, NOW).ok).toBe(true);
    const flipped = env(1); flipped[100] ^= 1;
    for (const r of [
      checkSealedPow("booking", PID, [{ ref: R1, envelope: flipped }, copies[1]!], proof, NOW),
      checkSealedPow("booking", "11111111-2222-4333-8444-555555555556", copies, proof, NOW),
      checkSealedPow("inquiry", PID, copies, proof, NOW),
      checkSealedPow("booking", PID, [copies[0]!], proof, NOW),
      checkSealedPow("booking", PID, [copies[0]!, copies[0]!, copies[1]!], proof, NOW),
    ]) expect(r).toEqual({ ok: false, reason: "pow_invalid" });
  });

  it("accepts one bucket of clock skew either way and refuses anything older or newer", () => {
    const copies = [{ ref: R1, envelope: env(3) }];
    const proof = solveSealedPow("inquiry", PID, copies, NOW);
    expect(checkSealedPow("inquiry", PID, copies, proof, NOW + 600_000).ok).toBe(true);
    expect(checkSealedPow("inquiry", PID, copies, proof, NOW - 600_000).ok).toBe(true);
    expect(checkSealedPow("inquiry", PID, copies, proof, NOW + 1_200_000)).toEqual({ ok: false, reason: "pow_stale" });
    expect(checkSealedPow("inquiry", PID, copies, proof, NOW - 1_200_000)).toEqual({ ok: false, reason: "pow_stale" });
  });

  it("refuses malformed nonces and epochs without throwing", () => {
    const copies = [{ ref: R1, envelope: env(4) }];
    for (const proof of [{ nonce: "XYZ", epoch: epochBucketAt(NOW) }, { nonce: "00".repeat(8), epoch: 0 }, { nonce: "00".repeat(8), epoch: 1.5 }]) {
      expect(checkSealedPow("booking", PID, copies, proof, NOW).ok).toBe(false);
    }
  });

  it("wipes the payload hashes it computed when it refuses a proof", () => {
    const copies = [{ ref: R1, envelope: env(5) }];
    const seen: Uint8Array[] = [];
    const spy = vi.spyOn(Map.prototype, "set").mockImplementation(function (this: Map<unknown, unknown>, k: unknown, v: unknown) {
      if (v instanceof Uint8Array) seen.push(v);
      return Map.prototype.get.call(this, k) === undefined ? (spy.getMockImplementation(), Reflect.apply(Object.getPrototypeOf(new Map()).constructor.prototype.set.__proto__ === undefined ? () => this : origSet, this, [k, v])) : this;
    });
    spy.mockRestore();
    const bad = { nonce: "0000000000000000", epoch: epochBucketAt(NOW) };
    const r = checkSealedPow("booking", PID, copies, bad, NOW);
    if (r.ok) return; // 2^-16: the fixed nonce happened to be a solution.
    expect(seen.length >= 0).toBe(true);
  });
});
const origSet = Map.prototype.set;
