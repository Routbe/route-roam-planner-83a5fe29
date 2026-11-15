import { beforeEach, describe, expect, it, vi } from "vitest";
import { hostBookingKeys } from "@/lib/crypto-enclave/booking-seal";
import { b64uEncode, hostRefOf } from "./sealed-booking";

const calls: { text: string; values: unknown[] }[] = [];
let reply: (text: string) => unknown[] = () => [];
vi.mock("@/lib/neon", () => ({
  sql: vi.fn(async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.join("?");
    calls.push({ text, values });
    return reply(text);
  }),
  withDbContext: vi.fn(),
}));
let legacyObject: Uint8Array | null = null;
vi.mock("@/lib/storage/s3.server", () => ({
  storageConfigured: vi.fn(() => true),
  getObject: vi.fn(async () => (legacyObject ? new Response(legacyObject) : new Response(null, { status: 404 }))),
  putObject: vi.fn(async () => { throw new Error("no object-storage writes allowed"); }),
}));
vi.mock("./sealed-schema.server", async (orig) => ({ ...(await orig<typeof import("./sealed-schema.server")>()), sealedSchemaReady: vi.fn(async () => true) }));

const U1 = "00000000-0000-4000-8000-0000000000b1";
const seal = "v1." + "A".repeat(16) + "." + "B".repeat(64);
const docFor = (fill: number) => {
  const k = hostBookingKeys(new Uint8Array(32).fill(fill));
  return { v: 1, kid: b64uEncode(k.kid), publicKey: b64uEncode(k.publicKey), sealedSeed: seal, keyId: "wk_1" };
};
const publicFor = (fill: number) => {
  const d = docFor(fill);
  return { ref: hostRefOf(hostBookingKeys(new Uint8Array(32).fill(fill)).publicKey), kid: d.kid, publicKey: d.publicKey };
};

beforeEach(() => {
  calls.length = 0;
  reply = () => [];
  legacyObject = null;
});

describe("host booking keys live in Neon (db/0278)", () => {
  it("publishes through rout_booking_host_key_publish with the key's own reference, never the user id", async () => {
    const { publishOwnBookingKey } = await import("./host-booking-key.server");
    reply = () => [{ r: { ok: true, kid: docFor(1).kid } }];
    expect(await publishOwnBookingKey(docFor(1), false)).toEqual({ ok: true, kid: docFor(1).kid });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.text).toContain("rout_booking_host_key_publish");
    expect(calls[0]!.values[0]).toBe(publicFor(1).ref);
    expect(calls[0]!.values).not.toContain(U1);
    expect(calls[0]!.values.at(-1)).toBe(false);
  });

  it("refuses a document whose kid is not the key id of its public key, before any database call", async () => {
    const { publishOwnBookingKey } = await import("./host-booking-key.server");
    expect(await publishOwnBookingKey({ ...docFor(1), kid: docFor(2).kid }, false)).toEqual({ ok: false, reason: "input" });
    expect(await publishOwnBookingKey({ ...docFor(1), extra: 1 }, false)).toEqual({ ok: false, reason: "input" });
    expect(calls).toHaveLength(0);
  });

  it("passes the database's refusal to replace another key through unchanged", async () => {
    const { publishOwnBookingKey } = await import("./host-booking-key.server");
    reply = () => [{ r: { ok: false, reason: "exists" } }];
    expect(await publishOwnBookingKey(docFor(2), false)).toEqual({ ok: false, reason: "exists" });
  });

  it("an event type is bookable only when every host has a key that matches its reference and kid", async () => {
    const { eventTypeHostKeys } = await import("./host-booking-key.server");
    reply = () => [{ r: { hosts: 2, keys: [publicFor(1)] } }];
    expect(await eventTypeHostKeys(U1)).toEqual({ ok: false, reason: "host_key_missing" });
    reply = () => [{ r: { hosts: 0, keys: [] } }];
    expect(await eventTypeHostKeys(U1)).toEqual({ ok: false, reason: "inactive" });
    reply = () => [{ r: { hosts: 2, keys: [publicFor(1), { ...publicFor(2), ref: publicFor(1).ref }] } }];
    expect(await eventTypeHostKeys(U1)).toEqual({ ok: false, reason: "host_key_missing" });
    reply = () => [{ r: { hosts: 2, keys: [publicFor(1), publicFor(2)] } }];
    const r = await eventTypeHostKeys(U1);
    expect(r.ok && r.hosts.map((h) => h.ref)).toEqual([publicFor(1).ref, publicFor(2).ref]);
  });

  it("a legacy object-storage key is carried into Neon unchanged and never written back", async () => {
    const { ownBookingKey } = await import("./host-booking-key.server");
    legacyObject = new TextEncoder().encode(JSON.stringify(docFor(3)));
    reply = (text) => (text.includes("rout_booking_host_key_publish") ? [{ r: { ok: true, kid: docFor(3).kid } }] : []);
    expect(await ownBookingKey(U1)).toEqual(docFor(3));
    expect(calls.map((c) => c.text.includes("rout_booking_host_key_publish"))).toEqual([false, true]);
    expect(calls[1]!.values.at(-1)).toBe(false);
    const s3 = await import("@/lib/storage/s3.server");
    expect(s3.putObject).not.toHaveBeenCalled();
  });
});
