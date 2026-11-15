import { describe, expect, it } from "vitest";
import { hostBookingKeys, sealBookingPayload, openBookingPayload } from "@/lib/crypto-enclave/booking-seal";
import { b64uDecode, b64uEncode, HOST_ENVELOPE_SIZES, hostRefOf, isHostEnvelopeFor, isSealedGuestEmail, parseSealedIntake, SEALED_GUEST_NAME, sealedGuestEmail } from "./sealed-booking";

const PID = "11111111-2222-4333-8444-555555555555";
const host = hostBookingKeys(new Uint8Array(32).fill(7));
const other = hostBookingKeys(new Uint8Array(32).fill(8));
const ref = hostRefOf(host.publicKey);

describe("sealed guest details: wire format", () => {
  it("binds envelopes to a UUID derived from the host key, never the user id", () => {
    expect(ref).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(hostRefOf(host.publicKey)).toBe(ref);
    expect(hostRefOf(other.publicKey)).not.toBe(ref);
  });

  it("placeholders satisfy the rout_booking_create checks and can never receive mail", () => {
    const email = sealedGuestEmail(PID);
    expect(SEALED_GUEST_NAME.trim().length).toBeGreaterThanOrEqual(1);
    expect(SEALED_GUEST_NAME.length).toBeLessThanOrEqual(120);
    expect(email.length).toBeGreaterThanOrEqual(3);
    expect(email.length).toBeLessThanOrEqual(254);
    expect(email.indexOf("@")).toBeGreaterThanOrEqual(1);
    expect(email.endsWith(".invalid")).toBe(true);
    expect(isSealedGuestEmail(email)).toBe(true);
    expect(isSealedGuestEmail("gast@example.com")).toBe(false);
  });

  it("name and e-mail travel inside the host envelope and open only for that host", () => {
    const sealed = sealBookingPayload({ hostUserId: ref, payloadId: PID, payload: { name: "Ada", email: "ada@example.com", note: "hi" }, hostPublicKey: host.publicKey });
    expect(openBookingPayload({ envelope: sealed.host, copy: "host", hostUserId: ref, payloadId: PID, secretKey: host.secretKey }))
      .toEqual({ name: "Ada", email: "ada@example.com", note: "hi" });
    expect(() => openBookingPayload({ envelope: sealed.host, copy: "host", hostUserId: ref, payloadId: PID, secretKey: other.secretKey })).toThrow();
  });

  it("the header check accepts a real bkh envelope for the right key id only", () => {
    const env = sealBookingPayload({ hostUserId: ref, payloadId: PID, payload: { name: "Ada" }, hostPublicKey: host.publicKey }).host;
    expect(HOST_ENVELOPE_SIZES).toContain(env.length);
    expect(isHostEnvelopeFor(env, host.kid)).toBe(true);
    expect(isHostEnvelopeFor(env, other.kid)).toBe(false);
    const kind = env.slice(); kind[5] = 6;
    expect(isHostEnvelopeFor(kind, host.kid)).toBe(false);
    const holder = env.slice(); holder[6] = 1;
    expect(isHostEnvelopeFor(holder, host.kid)).toBe(false);
    expect(isHostEnvelopeFor(env.subarray(0, env.length - 1), host.kid)).toBe(false);
    expect(isHostEnvelopeFor(new TextEncoder().encode("Ada Lovelace, ada@example.com"), host.kid)).toBe(false);
  });

  it("base64url decoding is strict", () => {
    const b = new Uint8Array([1, 2, 3, 250]);
    expect(b64uDecode(b64uEncode(b))).toEqual(b);
    expect(b64uDecode("AQID+g==")).toBeNull();
    expect(b64uDecode("a b")).toBeNull();
  });

  it("reads only v2 sealed intake values", () => {
    expect(parseSealedIntake({ v: 2, pid: PID, hosts: { [ref]: "AAAA" } })).toEqual({ v: 2, pid: PID, hosts: { [ref]: "AAAA" } });
    expect(parseSealedIntake({ v: 1, plain: { q: "a" } })).toBeNull();
    expect(parseSealedIntake({ v: 2, pid: PID, hosts: {} })).toBeNull();
    expect(parseSealedIntake({ v: 2, pid: PID, hosts: { [ref]: "AAAA" }, name: "Ada" })).toBeNull();
  });
});
