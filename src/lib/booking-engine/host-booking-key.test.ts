import { describe, expect, it } from "vitest";
import { hostBookingKeys } from "@/lib/crypto-enclave/booking-seal";
import { b64uEncode } from "./sealed-booking";
import { bookingKeyObjectKey, eventTypeHostKeys, publishBookingKey, readBookingKey, type BookingKeyStore } from "./host-booking-key.server";

const U1 = "00000000-0000-4000-8000-0000000000b1";
const U2 = "00000000-0000-4000-8000-0000000000b2";
const seal = "v1." + "A".repeat(16) + "." + "B".repeat(64);
const docFor = (fill: number) => {
  const k = hostBookingKeys(new Uint8Array(32).fill(fill));
  return { v: 1, kid: b64uEncode(k.kid), publicKey: b64uEncode(k.publicKey), sealedSeed: seal, keyId: "wk_1" };
};
function memoryStore(): BookingKeyStore & { data: Map<string, Uint8Array> } {
  const data = new Map<string, Uint8Array>();
  return { data, get: async (k) => data.get(k) ?? null, put: async (k, v) => { data.set(k, v); } };
}

describe("host booking key documents", () => {
  it("stores the member's own document under users/<uid>/booking-key.json", async () => {
    const store = memoryStore();
    expect(await publishBookingKey(store, U1, docFor(1), false)).toEqual({ ok: true, kid: docFor(1).kid });
    expect([...store.data.keys()]).toEqual([bookingKeyObjectKey(U1)]);
    expect(await readBookingKey(store, U1)).toEqual(docFor(1));
  });

  it("refuses a document whose kid is not the key id of its public key", async () => {
    const store = memoryStore();
    expect(await publishBookingKey(store, U1, { ...docFor(1), kid: docFor(2).kid }, false)).toEqual({ ok: false, reason: "input" });
    expect(await publishBookingKey(store, U1, { ...docFor(1), extra: 1 }, false)).toEqual({ ok: false, reason: "input" });
    expect(store.data.size).toBe(0);
  });

  it("never silently replaces a published key; replacing needs the explicit choice", async () => {
    const store = memoryStore();
    await publishBookingKey(store, U1, docFor(1), false);
    expect(await publishBookingKey(store, U1, docFor(2), false)).toEqual({ ok: false, reason: "exists" });
    expect((await readBookingKey(store, U1))?.kid).toBe(docFor(1).kid);
    expect(await publishBookingKey(store, U1, docFor(1), false)).toEqual({ ok: true, kid: docFor(1).kid });
    expect(await publishBookingKey(store, U1, docFor(2), true)).toEqual({ ok: true, kid: docFor(2).kid });
  });

  it("an event type is bookable only when every host has a valid key", async () => {
    const store = memoryStore();
    await publishBookingKey(store, U1, docFor(1), false);
    expect(await eventTypeHostKeys(store, [U1, U2])).toEqual({ ok: false, reason: "host_key_missing" });
    expect(await eventTypeHostKeys(store, [])).toEqual({ ok: false, reason: "inactive" });
    await publishBookingKey(store, U2, docFor(2), false);
    const r = await eventTypeHostKeys(store, [U1, U2]);
    expect(r.ok && r.hosts.map((h) => h.hostUserId)).toEqual([U1, U2]);
  });
});
