import { beforeEach, describe, expect, it, vi } from "vitest";
import { hostBookingKeys, sealBookingPayload } from "@/lib/crypto-enclave/booking-seal";
import { b64uEncode, hostRefOf, MAX_SEALED_INTAKE_BYTES } from "./sealed-booking";
import { parseBookingRequest, PLAINTEXT_GUEST_FIELDS } from "./types";

const calls: unknown[][] = [];
vi.mock("@/lib/neon", () => ({
  sql: vi.fn(async (_strings: TemplateStringsArray, ...values: unknown[]) => {
    calls.push(values);
    return [{ r: { ok: true, bookingIds: ["b1"], hostIds: ["00000000-0000-4000-8000-0000000000a1"], token: "t", status: "requested", holdExpiresAt: null, groupId: null } }];
  }),
  withDbContext: vi.fn(),
}));
vi.mock("./public.server", () => ({
  publicEventType: vi.fn(async (id: string) => ({ id, hostCount: 1, priceCents: null, holdMinutes: null, customFields: [] })),
}));
const host = hostBookingKeys(new Uint8Array(32).fill(3));
const other = hostBookingKeys(new Uint8Array(32).fill(4));
const ref = hostRefOf(host.publicKey);
const hostKeys = { ok: true as const, hosts: [{ hostUserId: "00000000-0000-4000-8000-0000000000a1", ref, kid: host.kid, publicKey: b64uEncode(host.publicKey) }] };
vi.mock("./host-booking-key.server", () => ({
  bookingKeyStorageReady: vi.fn(async () => true),
  productionBookingKeyStore: vi.fn(async () => ({})),
  eventTypeHostIds: vi.fn(async () => ["00000000-0000-4000-8000-0000000000a1"]),
  eventTypeHostKeys: vi.fn(async () => hostKeys),
}));

const PID = "11111111-2222-4333-8444-555555555555";
const ET = "22222222-3333-4444-8555-666666666666";
const envelopeFor = (pk: Uint8Array, r = ref) => b64uEncode(sealBookingPayload({ hostUserId: r, payloadId: PID, payload: { name: "Ada Lovelace", email: "ada@example.com", note: "allergie" }, hostPublicKey: pk }).host);
const request = (hosts: Record<string, string>) => ({ eventTypeId: ET, startUtc: "2026-12-01T10:00:00.000Z", guestTimezone: "Europe/Brussels", sealed: { pid: PID, hosts } });

beforeEach(() => { calls.length = 0; });

describe("booking create refuses plaintext guest details (Fase 1)", () => {
  it.each(PLAINTEXT_GUEST_FIELDS)("a request with %s is refused before validation", (field) => {
    expect(() => parseBookingRequest({ ...request({ [ref]: envelopeFor(host.publicKey) }), [field]: "Ada" })).toThrow("plaintext_refused");
  });

  it("any other extra key is refused too", () => {
    expect(() => parseBookingRequest({ ...request({ [ref]: envelopeFor(host.publicKey) }), name: "Ada" })).toThrow();
  });

  it("the database receives only placeholders and envelopes, never the guest's name, address or note", async () => {
    const { bookSlot } = await import("./book.server");
    const r = await bookSlot(parseBookingRequest(request({ [ref]: envelopeFor(host.publicKey) })));
    expect(r.ok).toBe(true);
    const sent = JSON.stringify(calls);
    expect(sent).not.toContain("Ada");
    expect(sent).not.toContain("ada@example.com");
    expect(sent).not.toContain("allergie");
    const values = calls[0]!;
    expect(values).toContain("RVE1");
    expect(values).toContain(`${PID}@sealed.invalid`);
    const intake = JSON.parse(values.find((v) => typeof v === "string" && v.startsWith("{")) as string);
    expect(intake.v).toBe(2);
    expect(Object.keys(intake.hosts)).toEqual([ref]);
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
    expect(calls).toHaveLength(0);
  });

  it("refuses when a host has no published booking key", async () => {
    const keys = await import("./host-booking-key.server");
    vi.mocked(keys.eventTypeHostKeys).mockResolvedValueOnce({ ok: false, reason: "host_key_missing" });
    const { bookSlot } = await import("./book.server");
    expect(await bookSlot(parseBookingRequest(request({ [ref]: envelopeFor(host.publicKey) })))).toEqual({ ok: false, reason: "host_key_missing" });
  });

  it("keeps the stored value under the database's 64 KiB intake limit", () => {
    expect(MAX_SEALED_INTAKE_BYTES).toBeLessThan(65536);
  });
});
