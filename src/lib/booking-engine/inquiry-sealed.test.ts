import { beforeEach, describe, expect, it, vi } from "vitest";
import { blake3 } from "@noble/hashes/blake3.js";
import { hostBookingKeys, openBookingPayload, sealBookingPayload } from "@/lib/crypto-enclave/booking-seal";
import { solveSealedPow } from "@/lib/crypto-enclave/sealed-pow";
import { b64uDecode, b64uEncode, hostRefOf } from "./sealed-booking";
import { inquiryObjectKey, parseInquiryRequest, PLAINTEXT_INQUIRY_FIELDS } from "./sealed-inquiry";

const HOST = "00000000-0000-4000-8000-0000000000a1";
const PID = "11111111-2222-4333-8444-555555555555";
const host = hostBookingKeys(new Uint8Array(32).fill(3));
const other = hostBookingKeys(new Uint8Array(32).fill(4));
const ref = hostRefOf(host.publicKey);

const calls: { text: string; values: unknown[] }[] = [];
let createReply: Record<string, unknown> = { ok: true, id: "i1" };
let sealedRows: Record<string, unknown>[] = [];
let legacyRows: Record<string, unknown>[] = [];
vi.mock("@/lib/neon", () => ({
  sql: vi.fn(async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.join("?");
    calls.push({ text, values });
    if (text.includes("rout_inquiry_create_sealed")) return [{ r: createReply }];
    if (text.includes("from public.inquiries")) return sealedRows;
    if (text.includes("from public.booking_requests")) return legacyRows;
    return [];
  }),
  withDbContext: vi.fn(),
}));
const schema = { ready: true };
vi.mock("./sealed-schema.server", async (orig) => ({ ...(await orig<typeof import("./sealed-schema.server")>()), sealedSchemaReady: vi.fn(async () => schema.ready) }));
const lookups = { host: 0 };
vi.mock("@/lib/booking.server", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/booking.server")>()),
  hostFor: vi.fn(async () => { lookups.host++; return { id: HOST, username: "host", display_name: "Host", email: "host@example.org", config: { duration: 30, title: "Intro" } }; }),
}));
vi.mock("./host-booking-key.server", () => ({
  profileHostKey: vi.fn(async () => ({ ref, kid: host.kid, publicKey: b64uEncode(host.publicKey) })),
}));
vi.mock("@/lib/brevo/client", () => ({
  sendSealedBookingRequestToHost: vi.fn(async () => ({ sent: true })),
  sendBookingConfirmedToGuest: vi.fn(async () => ({ sent: true })),
  sendBookingDeclinedToGuest: vi.fn(async () => ({ sent: true })),
}));
vi.mock("@/lib/storage/s3.server", () => ({
  storageConfigured: vi.fn(() => true),
  getObject: vi.fn(async () => new Response(null, { status: 404 })),
  putObject: vi.fn(async () => { throw new Error("no object-storage writes allowed"); }),
}));

const envelopeFor = (pk: Uint8Array, r = ref) =>
  b64uEncode(sealBookingPayload({ hostUserId: r, payloadId: PID, payload: { name: "Ada Lovelace", email: "ada@example.com", note: "allergie" }, hostPublicKey: pk }).host);
const proofFor = (sealed: { ref: string; envelope: string }, now = Date.now()) => solveSealedPow("inquiry", PID, [{ ref: sealed.ref, envelope: b64uDecode(sealed.envelope)! }], now);
const request = (sealed: { pid: string; ref: string; envelope: string }, pow = proofFor(sealed)) => ({ handle: "host", preferredDate: "2099-12-01", preferredTime: "10:30", sealed, pow });

beforeEach(() => {
  calls.length = 0;
  createReply = { ok: true, id: "i1" };
  sealedRows = [];
  legacyRows = [];
  schema.ready = true;
  lookups.host = 0;
  vi.clearAllMocks();
});

describe("profile-card requests refuse plaintext guest details", () => {
  it.each(PLAINTEXT_INQUIRY_FIELDS)("a request with %s is refused before validation", (field) => {
    expect(() => parseInquiryRequest({ ...request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) }), [field]: "Ada" })).toThrow("plaintext_refused");
  });

  it("the old plaintext request shape is refused", () => {
    expect(() => parseInquiryRequest({ handle: "host", guestName: "Ada", guestEmail: "ada@example.com", preferredDate: "2099-12-01", preferredTime: "10:30" })).toThrow("plaintext_refused");
  });

  it("a request without an envelope, without a proof or with an extra key is refused", () => {
    expect(() => parseInquiryRequest({ handle: "host", preferredDate: "2099-12-01", preferredTime: "10:30" })).toThrow();
    const { pow: _pow, ...noPow } = request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) });
    expect(() => parseInquiryRequest(noPow)).toThrow();
    expect(() => parseInquiryRequest({ ...request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) }), extra: "x" })).toThrow();
  });
});

describe("createSealedInquiry", () => {
  it("a wrong or stale proof is refused before any database call or host lookup", async () => {
    const { createSealedInquiry } = await import("./inquiry.server");
    const sealed = { pid: PID, ref, envelope: envelopeFor(host.publicKey) };
    const good = proofFor(sealed);
    const bad = { ...good, nonce: good.nonce === "ffffffffffffffff" ? "fffffffffffffffe" : "ffffffffffffffff" };
    expect(await createSealedInquiry(parseInquiryRequest(request(sealed, bad)))).toEqual({ ok: false, reason: "pow_invalid" });
    expect(await createSealedInquiry(parseInquiryRequest(request(sealed, proofFor(sealed, Date.now() - 30 * 60_000))))).toEqual({ ok: false, reason: "pow_stale" });
    expect(calls).toHaveLength(0);
    expect(lookups.host).toBe(0);
  });

  it("stores envelope, BLAKE3 hash, nonce and epoch in Neon; no object storage, no guest details anywhere", async () => {
    const { createSealedInquiry } = await import("./inquiry.server");
    const sealed = { pid: PID, ref, envelope: envelopeFor(host.publicKey) };
    const req = request(sealed);
    expect(await createSealedInquiry(parseInquiryRequest(req))).toEqual({ ok: true, pid: PID });
    const create = calls.find((c) => c.text.includes("rout_inquiry_create_sealed"))!;
    expect(create.values).toContain(sealed.envelope);
    expect(create.values).toContain(Array.from(blake3(b64uDecode(sealed.envelope)!), (b) => b.toString(16).padStart(2, "0")).join(""));
    expect(create.values).toContain(req.pow.nonce);
    expect(create.values).toContain(req.pow.epoch);
    const brevo = await import("@/lib/brevo/client");
    const s3 = await import("@/lib/storage/s3.server");
    expect(s3.putObject).not.toHaveBeenCalled();
    // The envelope is random base64url and can contain a short name by chance; it is checked to be
    // the sealed bytes above, so the plaintext search covers everything else that left the server.
    const scrub = (v: unknown) => (v === sealed.envelope ? "<envelope>" : v);
    const everything = JSON.stringify({
      calls: calls.map((c) => ({ ...c, values: c.values.map(scrub) })),
      mail: vi.mocked(brevo.sendSealedBookingRequestToHost).mock.calls,
    });
    for (const secret of ["Ada", "ada@example.com", "allergie"]) expect(everything).not.toContain(secret);
  });

  it("the host's key opens what was stored", async () => {
    const { createSealedInquiry } = await import("./inquiry.server");
    const sealed = { pid: PID, ref, envelope: envelopeFor(host.publicKey) };
    await createSealedInquiry(parseInquiryRequest(request(sealed)));
    const stored = calls.find((c) => c.text.includes("rout_inquiry_create_sealed"))!.values.find((v) => v === sealed.envelope) as string;
    expect(openBookingPayload({ envelope: b64uDecode(stored)!, copy: "host", hostUserId: ref, payloadId: PID, secretKey: host.secretKey })).toEqual({ name: "Ada Lovelace", email: "ada@example.com", note: "allergie" });
  });

  it("refuses plaintext disguised as an envelope, another host's key or a wrong reference", async () => {
    const { createSealedInquiry } = await import("./inquiry.server");
    const otherRef = hostRefOf(other.publicKey);
    for (const sealed of [
      { pid: PID, ref, envelope: b64uEncode(new TextEncoder().encode("Ada Lovelace ada@example.com")) },
      { pid: PID, ref, envelope: envelopeFor(other.publicKey) },
      { pid: PID, ref: otherRef, envelope: envelopeFor(other.publicKey, otherRef) },
    ]) {
      expect(await createSealedInquiry(parseInquiryRequest(request(sealed)))).toEqual({ ok: false, reason: "invalid" });
    }
    expect(calls.filter((c) => c.text.includes("rout_inquiry_create_sealed"))).toHaveLength(0);
  });

  it("a replayed proof or payload id (database: duplicate) is refused as invalid", async () => {
    createReply = { ok: false, reason: "duplicate" };
    const { createSealedInquiry } = await import("./inquiry.server");
    expect(await createSealedInquiry(parseInquiryRequest(request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) })))).toEqual({ ok: false, reason: "invalid" });
  });

  it("passes the database's rate limit through", async () => {
    createReply = { ok: false, reason: "rate_limited" };
    const { createSealedInquiry } = await import("./inquiry.server");
    expect(await createSealedInquiry(parseInquiryRequest(request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) })))).toEqual({ ok: false, reason: "rate_limited" });
  });

  it("fails closed while db/0278 is not applied, and when the host has no key", async () => {
    const { createSealedInquiry } = await import("./inquiry.server");
    schema.ready = false;
    expect(await createSealedInquiry(parseInquiryRequest(request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) })))).toEqual({ ok: false, reason: "unavailable" });
    schema.ready = true;
    const keys = await import("./host-booking-key.server");
    vi.mocked(keys.profileHostKey).mockResolvedValueOnce(null);
    expect(await createSealedInquiry(parseInquiryRequest(request({ pid: PID, ref, envelope: envelopeFor(host.publicKey) })))).toEqual({ ok: false, reason: "host_key_missing" });
    expect(calls.filter((c) => c.text.includes("rout_inquiry_create_sealed"))).toHaveLength(0);
  });
});

describe("host reads", () => {
  it("lists sealed requests from Neon and older ones from booking_requests and legacy documents", async () => {
    const { listHostInquiries } = await import("./inquiry.server");
    const envelope = envelopeFor(host.publicKey);
    sealedRows = [{ id: "n1", payload_id: PID, host_ref: ref, encrypted_rve1_payload: envelope, preferred_date: "2099-12-01", preferred_time: "10:30", duration_minutes: 30, title: "Intro", status: "pending", created_at: "2026-11-15T10:00:00.000Z" }];
    const OLD = "99999999-2222-4333-8444-555555555555";
    legacyRows = [{ id: "o1", guest_name: "RVE1", guest_email: `${OLD}@sealed.invalid`, guest_message: null, preferred_date: "2099-11-01", preferred_time: "09:00", duration_minutes: 30, title: null, status: "pending", created_at: "2026-11-01T10:00:00.000Z" }];
    const doc = { v: 1, pid: OLD, ref, envelope };
    const reader = { get: async (k: string) => (k === inquiryObjectKey(HOST, OLD) ? new TextEncoder().encode(JSON.stringify(doc)) : null) };
    const list = await listHostInquiries(HOST, reader);
    expect(list.map((i) => [i.id, i.sealed?.pid])).toEqual([["n1", PID], ["o1", OLD]]);
  });
});

describe("deciding a legacy sealed request", () => {
  it("sends no mail to the guest", async () => {
    const { sql } = await import("@/lib/neon");
    vi.mocked(sql).mockImplementation((async (strings: TemplateStringsArray) => {
      const text = strings.join("?");
      if (text.includes("rout_booking_request_resolve")) return [{ id: "r1", profile_id: HOST, guest_name: "RVE1", guest_email: `${PID}@sealed.invalid`, preferred_date: "2099-12-01", preferred_time: "10:30", guest_message: null, duration_minutes: 30, title: "Intro" }];
      if (text.includes("from public.profiles")) return [{ display_name: "Host", username: "host" }];
      return [];
    }) as never);
    const { resolveBookingRequest } = await import("@/lib/booking.server");
    const brevo = await import("@/lib/brevo/client");
    expect((await resolveBookingRequest("r1", "accept")).ok).toBe(true);
    expect((await resolveBookingRequest("r1", "decline")).ok).toBe(true);
    expect(brevo.sendBookingConfirmedToGuest).not.toHaveBeenCalled();
    expect(brevo.sendBookingDeclinedToGuest).not.toHaveBeenCalled();
  });
});
