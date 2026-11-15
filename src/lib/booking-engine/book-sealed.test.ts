import { beforeEach, describe, expect, it, vi } from "vitest";
import { blake3 } from "@noble/hashes/blake3.js";
import { hostBookingKeys, sealBookingPayload } from "@/lib/crypto-enclave/booking-seal";
import { epochBucketAt, solveSealedPow } from "@/lib/crypto-enclave/sealed-pow";
import { b64uDecode, b64uEncode, hostRefOf } from "./sealed-booking";
import { parseBookingRequest, PLAINTEXT_GUEST_FIELDS } from "./types";

const calls: { text: string; values: unknown[] }[] = [];
let failWith: unknown = null;
vi.mock("@/lib/neon", () => ({
  sql: vi.fn(async (strings: TemplateStringsArray, ...values: unknown[]) => {
    calls.push({ text: strings.join("?"), values });
    if (failWith) throw failWith;
    return [{ r: { ok: true, bookingIds: ["b1"], hostIds: ["00000000-0000-4000-8000-0000000000a1"], token: "t", status: "requested", holdExpiresAt: null, groupId: null } }];
  }),
  withDbContext: vi.fn(),
}));
const schema = { ready: true };
vi.mock("./sealed-schema.server", async (orig) => ({ ...(await orig<typeof import("./sealed-schema.server")>()), sealedSchemaReady: vi.fn(async () => schema.ready) }));
const lookups = { eventType: 0 };
vi.mock("./public.server", () => ({
  publicEventType: vi.fn(async (id: string) => { lookups.eventType++; return { id, hostCount: 1, priceCents: null, holdMinutes: null, customFields: [] }; }),
}));
const host = hostBookingKeys(new Uint8Array(32).fill(3));
const other = hostBookingKeys(new Uint8Array(32).fill(4));
const ref = hostRefOf(host.publicKey);
const hostKeys = { ok: true as const, hosts: [{ ref, kid: host.kid, publicKey: b64uEncode(host.publicKey) }] };
vi.mock("./host-booking-key.server", () => ({ eventTypeHostKeys: vi.fn(async () => hostKeys) }));

const PID = "11111111-2222-4333-8444-555555555555";
const ET = "22222222-3333-4444-8555-666666666666";
const envelopeFor = (pk: Uint8Array, r = ref) => b64uEncode(sealBookingPayload({ hostUserId: r, payloadId: PID, payload: { name: "Ada Lovelace", email: "ada@example.com", note: "allergie" }, hostPublicKey: pk }).host);
const proofFor = (hosts: Record<string, string>, now = Date.now()) =>
  solveSealedPow("booking", PID, Object.entries(hosts).map(([r, e]) => ({ ref: r, envelope: b64uDecode(e)! })), now);
const request = (hosts: Record<string, string>, pow = proofFor(hosts)) => ({ eventTypeId: ET, startUtc: "2026-12-01T10:00:00.000Z", guestTimezone: "Europe/Brussels", sealed: { pid: PID, hosts }, pow });

beforeEach(() => { calls.length = 0; failWith = null; schema.ready = true; lookups.eventType = 0; });

describe("booking create refuses plaintext guest details", () => {
  it.each(PLAINTEXT_GUEST_FIELDS)("a request with %s is refused before validation", (field) => {
    expect(() => parseBookingRequest({ ...request({ [ref]: envelopeFor(host.publicKey) }), [field]: "Ada" })).toThrow("plaintext_refused");
  });

  it("any other extra key, or a missing proof-of-work, is refused too", () => {
    expect(() => parseBookingRequest({ ...request({ [ref]: envelopeFor(host.publicKey) }), name: "Ada" })).toThrow();
    const { pow: _pow, ...noPow } = request({ [ref]: envelopeFor(host.publicKey) });
    expect(() => parseBookingRequest(noPow)).toThrow();
  });
});

describe("proof-of-work is checked before any database interaction", () => {
  it("a wrong nonce is refused with no database call and no event-type lookup", async () => {
    const { bookSlot } = await import("./book.server");
    const hosts = { [ref]: envelopeFor(host.publicKey) };
    const good = proofFor(hosts);
    const bad = { ...good, nonce: good.nonce === "0000000000000000" ? "0000000000000001" : "0000000000000000" };
    expect(await bookSlot(parseBookingRequest(request(hosts, bad)))).toEqual({ ok: false, reason: "pow_invalid" });
    expect(calls).toHaveLength(0);
    expect(lookups.eventType).toBe(0);
  });

  it("a proof for other ciphertext is refused: the nonce is bound to the exact envelope", async () => {
    const { bookSlot } = await import("./book.server");
    const proof = proofFor({ [ref]: envelopeFor(host.publicKey) });
    expect(await bookSlot(parseBookingRequest(request({ [ref]: envelopeFor(host.publicKey) }, proof)))).toEqual({ ok: false, reason: "pow_invalid" });
    expect(calls).toHaveLength(0);
  });

  it("a proof from an epoch more than one 10-minute bucket away is stale, with no database call", async () => {
    const { bookSlot } = await import("./book.server");
    const hosts = { [ref]: envelopeFor(host.publicKey) };
    const old = proofFor(hosts, Date.now() - 25 * 60_000);
    expect(old.epoch).toBeLessThan(epochBucketAt(Date.now()) - 1);
    expect(await bookSlot(parseBookingRequest(request(hosts, old)))).toEqual({ ok: false, reason: "pow_stale" });
    expect(calls).toHaveLength(0);
  });
});

describe("sealed bookings go to Neon through rout_booking_create_sealed", () => {
  it("sends only envelopes, their BLAKE3 hashes, nonce and epoch; never the guest's details", async () => {
    const { bookSlot } = await import("./book.server");
    const hosts = { [ref]: envelopeFor(host.publicKey) };
    const req = request(hosts);
    expect((await bookSlot(parseBookingRequest(req))).ok).toBe(true);
    expect(calls).toHaveLength(1);
    const { text, values } = calls[0]!;
    expect(text).toContain("rout_booking_create_sealed");
    // Envelopes are random base64url and can contain a short name by chance: blank them before searching.
    const scrubbed = JSON.stringify(values).split(hosts[ref]!).join("<envelope>");
    for (const secret of ["Ada", "ada@example.com", "allergie"]) expect(scrubbed).not.toContain(secret);
    const copies = JSON.parse(values.find((v) => typeof v === "string" && v.startsWith("[")) as string);
    const hash = Array.from(blake3(b64uDecode(hosts[ref]!)!), (b) => b.toString(16).padStart(2, "0")).join("");
    expect(copies).toEqual([{ ref, envelope: hosts[ref], hash }]);
    expect(values).toContain(req.pow.nonce);
    expect(values).toContain(req.pow.epoch);
  });

  it("refuses an envelope sealed to another key, a missing host or an extra host", async () => {
    const { bookSlot } = await import("./book.server");
    const otherRef = hostRefOf(other.publicKey);
    for (const hosts of [
      { [ref]: envelopeFor(other.publicKey) },
      { [otherRef]: envelopeFor(other.publicKey, otherRef) },
      { [ref]: envelopeFor(host.publicKey), [otherRef]: envelopeFor(other.publicKey, otherRef) },
      { [ref]: b64uEncode(new TextEncoder().encode("Ada Lovelace")) },
    ]) {
      expect(await bookSlot(parseBookingRequest(request(hosts)))).toEqual({ ok: false, reason: "invalid_intake" });
    }
    expect(calls.filter((c) => c.text.includes("rout_booking_create_sealed"))).toHaveLength(0);
  });

  it("fails closed while db/0278 is not applied", async () => {
    schema.ready = false;
    const { bookSlot } = await import("./book.server");
    expect(await bookSlot(parseBookingRequest(request({ [ref]: envelopeFor(host.publicKey) })))).toEqual({ ok: false, reason: "unavailable" });
    expect(calls).toHaveLength(0);
    expect(lookups.eventType).toBe(0);
  });

  it("a replayed proof (unique payload hash) is refused as invalid", async () => {
    failWith = Object.assign(new Error("duplicate key"), { code: "23505" });
    const { bookSlot } = await import("./book.server");
    expect(await bookSlot(parseBookingRequest(request({ [ref]: envelopeFor(host.publicKey) })))).toEqual({ ok: false, reason: "pow_invalid" });
  });

  it("refuses when a host has no published booking key", async () => {
    const keys = await import("./host-booking-key.server");
    vi.mocked(keys.eventTypeHostKeys).mockResolvedValueOnce({ ok: false, reason: "host_key_missing" });
    const { bookSlot } = await import("./book.server");
    expect(await bookSlot(parseBookingRequest(request({ [ref]: envelopeFor(host.publicKey) })))).toEqual({ ok: false, reason: "host_key_missing" });
  });
});
