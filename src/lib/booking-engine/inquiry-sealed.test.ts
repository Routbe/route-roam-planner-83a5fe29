import { beforeEach, describe, expect, it, vi } from "vitest";
import { hostBookingKeys, openBookingPayload, sealBookingPayload } from "@/lib/crypto-enclave/booking-seal";
import { b64uDecode, b64uEncode, hostRefOf } from "./sealed-booking";
import { inquiryObjectKey, parseInquiryRequest, PLAINTEXT_INQUIRY_FIELDS } from "./sealed-inquiry";
import type { InquiryStore } from "./inquiry.server";

const HOST = "00000000-0000-4000-8000-0000000000a1";
const PID = "11111111-2222-4333-8444-555555555555";
const host = hostBookingKeys(new Uint8Array(32).fill(3));
const other = hostBookingKeys(new Uint8Array(32).fill(4));
const ref = hostRefOf(host.publicKey);

const calls: unknown[][] = [];
let resolveRow: Record<string, unknown> | null = null;
vi.mock("@/lib/neon", () => ({
  sql: vi.fn(async (strings: TemplateStringsArray, ...values: unknown[]) => {
    calls.push(values);
    const text = strings.join("?");
    if (text.includes("rout_booking_request_resolve")) return resolveRow ? [resolveRow] : [];
    if (text.includes("from public.profiles")) return [{ display_name: "Host", username: "host" }];
    return [{ id: "r1" }];
  }),
  withDbContext: vi.fn(),
}));
vi.mock("@/lib/booking.server", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/booking.server")>()),
  hostFor: vi.fn(async () => ({ id: HOST, username: "host", display_name: "Host", email: "host@example.org", config: { duration: 30, title: "Intro" } })),
}));
vi.mock("./host-booking-key.server", () => ({
  bookingKeyStorageReady: vi.fn(async () => true),
  productionBookingKeyStore: vi.fn(async () => ({})),
  readBookingKey: vi.fn(async () => ({ publicKey: b64uEncode(host.publicKey), kid: b64uEncode(host.kid) })),
}));
vi.mock("@/lib/brevo/client", () => ({
  sendSealedBookingRequestToHost: vi.fn(async () => ({ sent: true })),
  sendBookingConfirmedToGuest: vi.fn(async () => ({ sent: true })),
  sendBookingDeclinedToGuest: vi.fn(async () => ({ sent: true })),
}));
vi.mock("@/lib/profile-private.server", () => ({ readNotifyAddress: vi.fn(async () => "host@example.org") }));

const memoryStore = (): InquiryStore & { data: Map<string, Uint8Array> } => {
  const data = new Map<string, Uint8Array>();
  return { data, get: async (k) => data.get(k) ?? null, put: async (k, b) => void data.set(k, b), remove: async (k) => void data.delete(k) };
};
const envelopeFor = (pk: Uint8Array, r = ref) =>
  b64uEncode(sealBookingPayload({ hostUserId: r, payloadId: PID, payload: { name: "Ada Lovelace", email: "ada@example.com", note: "allergie" }, hostPublicKey: pk }).host);
const request = (sealed: Record<string, string>) => ({ handle: "host", preferredDate: "2099-12-01", preferredTime: "10:30", sealed });

beforeEach(async () => {
  calls.length = 0;
  resolveRow = null;
  vi.clearAllMocks();
});

describe("profile-card requests refuse plaintext guest details", () => {
  it.each(PLAINTEXT_INQUIRY_FIELDS)("a request with %s is refused before validation", (field) => {
    expect(() => parseInquiryRequest({ ...request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) }), [field]: "Ada" })).toThrow("plaintext_refused");
  });

  it("the old plaintext request shape is refused", () => {
    expect(() => parseInquiryRequest({ handle: "host", guestName: "Ada", guestEmail: "ada@example.com", preferredDate: "2099-12-01", preferredTime: "10:30" })).toThrow("plaintext_refused");
  });

  it("a request without an envelope or with an extra key is refused", () => {
    expect(() => parseInquiryRequest({ handle: "host", preferredDate: "2099-12-01", preferredTime: "10:30" })).toThrow();
    expect(() => parseInquiryRequest({ ...request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) }), extra: "x" })).toThrow();
  });
});

describe("createSealedInquiry", () => {
  it("stores only the envelope and placeholders; neither database, storage nor mail sees the guest's details", async () => {
    const { createSealedInquiry } = await import("./inquiry.server");
    const store = memoryStore();
    const r = await createSealedInquiry(parseInquiryRequest(request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) })), store);
    expect(r).toEqual({ ok: true, pid: PID });
    const brevo = await import("@/lib/brevo/client");
    const everything = JSON.stringify({ calls, mail: vi.mocked(brevo.sendSealedBookingRequestToHost).mock.calls, stored: [...store.data.values()].map((b) => new TextDecoder().decode(b)) });
    for (const secret of ["Ada", "ada@example.com", "allergie"]) expect(everything).not.toContain(secret);
    expect(calls[0]).toContain("RVE1");
    expect(calls[0]).toContain(`${PID}@sealed.invalid`);
    expect(calls[0]).toContain(null);
    expect(store.data.has(inquiryObjectKey(HOST, PID))).toBe(true);
  });

  it("the host's key opens what was stored", async () => {
    const { createSealedInquiry } = await import("./inquiry.server");
    const store = memoryStore();
    await createSealedInquiry(parseInquiryRequest(request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) })), store);
    const doc = JSON.parse(new TextDecoder().decode(store.data.get(inquiryObjectKey(HOST, PID))!));
    const payload = openBookingPayload({ envelope: b64uDecode(doc.envelope)!, copy: "host", hostUserId: doc.ref, payloadId: doc.pid, secretKey: host.secretKey });
    expect(payload).toEqual({ name: "Ada Lovelace", email: "ada@example.com", note: "allergie" });
  });

  it("refuses plaintext disguised as an envelope, another host's key or a wrong reference", async () => {
    const { createSealedInquiry } = await import("./inquiry.server");
    const store = memoryStore();
    const otherRef = hostRefOf(other.publicKey);
    for (const sealed of [
      { pid: PID, ref, envelope: b64uEncode(new TextEncoder().encode("Ada Lovelace ada@example.com")) },
      { pid: PID, ref, envelope: envelopeFor(other.publicKey) },
      { pid: PID, ref: otherRef, envelope: envelopeFor(other.publicKey, otherRef) },
    ]) {
      expect(await createSealedInquiry(parseInquiryRequest(request(sealed)), store)).toEqual({ ok: false, reason: "invalid" });
    }
    expect(calls).toHaveLength(0);
    expect(store.data.size).toBe(0);
  });

  it("never overwrites an existing request with the same payload id", async () => {
    const { createSealedInquiry } = await import("./inquiry.server");
    const store = memoryStore();
    store.data.set(inquiryObjectKey(HOST, PID), new Uint8Array([1]));
    expect(await createSealedInquiry(parseInquiryRequest(request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) })), store)).toEqual({ ok: false, reason: "invalid" });
    expect(store.data.get(inquiryObjectKey(HOST, PID))).toEqual(new Uint8Array([1]));
  });

  it("refuses when the host has no published booking key", async () => {
    const keys = await import("./host-booking-key.server");
    vi.mocked(keys.readBookingKey).mockResolvedValueOnce(null);
    const { createSealedInquiry } = await import("./inquiry.server");
    expect(await createSealedInquiry(parseInquiryRequest(request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) })), memoryStore())).toEqual({ ok: false, reason: "host_key_missing" });
    expect(calls).toHaveLength(0);
  });
});

describe("deciding a sealed request", () => {
  it("sends no mail to the guest", async () => {
    resolveRow = { id: "r1", profile_id: HOST, guest_name: "RVE1", guest_email: `${PID}@sealed.invalid`, preferred_date: "2099-12-01", preferred_time: "10:30", guest_message: null, duration_minutes: 30, title: "Intro" };
    const { resolveBookingRequest } = await import("@/lib/booking.server");
    const brevo = await import("@/lib/brevo/client");
    expect((await resolveBookingRequest("r1", "accept")).ok).toBe(true);
    expect((await resolveBookingRequest("r1", "decline")).ok).toBe(true);
    expect(brevo.sendBookingConfirmedToGuest).not.toHaveBeenCalled();
    expect(brevo.sendBookingDeclinedToGuest).not.toHaveBeenCalled();
  });
});
