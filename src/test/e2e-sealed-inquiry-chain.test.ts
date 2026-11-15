// @vitest-environment node
/**
 * End-to-end chain of a sealed profile-card request on schema 0280, without mocks in the crypto
 * or the database path:
 *
 *   host device   crypto worker ops (runEnclaveOp): Master Key, bookingKey.ensure, published
 *                 through publishOwnBookingKey -> rout_booking_host_key_publish as rout_app
 *   visitor       profileBookingKey -> booking.seal (RVE1 bkh, ML-KEM-1024 + X25519) with the
 *                 BLAKE3 Hashcash proof solved in the worker
 *   server        createSealedInquiry: proof checked before any database call, then
 *                 rout_inquiry_create_sealed into public.inquiries (replay of db/ incl. 0278-0280)
 *   host Studio   listHostInquiries under RLS (rout.current_user_id) -> bookingKey.open
 *
 * Only the edges are stubbed: hostFor (profile lookup), mail and object storage (writes forbidden).
 * Every seed, secret key and padded plaintext the chain creates is captured and must be all
 * zero once the operation that made it returns.
 */
import "fake-indexeddb/auto";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { replayDb } from "../../scripts/formal-rls/replay";

const HOST = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const OTHER = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const day = new Date(Date.now() + 3 * 86400000).toISOString().slice(0, 10);
const PAYLOAD = { name: "Ada Lovelace", email: "ada@example.com", note: "Graag een rustige ruimte, notenallergie." };

const h = vi.hoisted(() => ({
  db: null as PGlite | null,
  caller: null as string | null,
  dbCalls: 0,
  secrets: [] as Uint8Array[],
  serverBuffers: [] as Uint8Array[],
}));

vi.mock("@/lib/neon", () => ({
  sql: async (strings: TemplateStringsArray, ...values: unknown[]) => {
    h.dbCalls++;
    const text = strings.reduce((acc, s, i) => acc + s + (i < values.length ? `$${i + 1}` : ""), "");
    const db = h.db!;
    await db.exec("reset role");
    await db.query("select set_config('rout.current_user_id', $1, false)", [h.caller ?? ""]);
    await db.exec("set role rout_app");
    return (await db.query(text, values)).rows;
  },
  withDbContext: vi.fn(),
}));
vi.mock("@/lib/booking.server", () => ({
  hostFor: async (handle: string) =>
    handle === "ann" ? { id: HOST, username: "ann", display_name: "Ann", email: null, config: { duration: 30, title: "Intro" } } : null,
}));
vi.mock("@/lib/brevo/client", () => ({ sendSealedBookingRequestToHost: vi.fn(async () => ({ sent: true })) }));
vi.mock("@/lib/storage/s3.server", () => ({
  storageConfigured: () => true,
  getObject: async () => new Response(null, { status: 404 }),
  putObject: async () => { throw new Error("object-storage writes are forbidden"); },
}));
// Capture every seed and secret key the RVE1 layer derives, and every padded plaintext it seals or opens.
vi.mock("@/lib/crypto-enclave/pqc-envelope", async (orig) => {
  const m = await orig<typeof import("@/lib/crypto-enclave/pqc-envelope")>();
  return {
    ...m,
    generateRecipientKeys: (holder: Parameters<typeof m.generateRecipientKeys>[0], seed?: Uint8Array) => {
      const k = m.generateRecipientKeys(holder, seed);
      if (seed) h.secrets.push(seed);
      h.secrets.push(k.secretKey);
      return k;
    },
    sealEnvelope: (input: Parameters<typeof m.sealEnvelope>[0]) => { h.secrets.push(input.plaintext); return m.sealEnvelope(input); },
    openEnvelope: (input: Parameters<typeof m.openEnvelope>[0]) => { const p = m.openEnvelope(input); h.secrets.push(p); return p; },
  };
});
// Capture the server's decoded envelope and its BLAKE3 hash.
vi.mock("@/lib/booking-engine/sealed-booking", async (orig) => {
  const m = await orig<typeof import("@/lib/booking-engine/sealed-booking")>();
  return { ...m, b64uDecode: (s: string) => { const b = m.b64uDecode(s); if (b && b.length > 1000) h.serverBuffers.push(b); return b; } };
});
vi.mock("@/lib/crypto-enclave/sealed-pow", async (orig) => {
  const m = await orig<typeof import("@/lib/crypto-enclave/sealed-pow")>();
  return {
    ...m,
    checkSealedPow: (...a: Parameters<typeof m.checkSealedPow>) => {
      const r = m.checkSealedPow(...a);
      if (r.ok) for (const x of r.hashes.values()) h.serverBuffers.push(x);
      return r;
    },
  };
});

const { runEnclaveOp } = await import("@/lib/crypto-enclave/enclave-core");
const { publishOwnBookingKey, readOwnBookingKey } = await import("@/lib/booking-engine/host-booking-key.server");
const { createSealedInquiry, listHostInquiries, profileBookingKey } = await import("@/lib/booking-engine/inquiry.server");
const { parseInquiryRequest } = await import("@/lib/booking-engine/sealed-inquiry");
const { b64uDecode, b64uEncode } = await import("@/lib/booking-engine/sealed-booking");
const { solveSealedPow } = await import("@/lib/crypto-enclave/sealed-pow");
const { resetSealedSchemaProbe } = await import("@/lib/booking-engine/sealed-schema.server");
type Ops = import("@/lib/crypto-enclave/protocol").EnclaveOps;
type Op = import("@/lib/crypto-enclave/protocol").EnclaveOp;

async function call<K extends Op>(op: K, args: Ops[K]["req"]): Promise<Ops[K]["res"]> {
  const r = await runEnclaveOp(op, args);
  if (!r.ok) throw new Error(r.code);
  return r.result as Ops[K]["res"];
}
const allWiped = (list: Uint8Array[]) => list.length > 0 && list.every((b) => b.every((x) => x === 0));
const drain = (list: Uint8Array[]) => list.splice(0, list.length);

beforeAll(async () => {
  h.db = await replayDb();
  await h.db.exec(`
    insert into public.users (id, email) values ('${HOST}', 'ann@example.org'), ('${OTHER}', 'bob@example.org');
    insert into public.profiles (id, username, blocks) values ('${HOST}', 'ann', '[{"kind":"booking_request"}]'), ('${OTHER}', 'bob', '[]')
      on conflict (id) do update set username = excluded.username, blocks = excluded.blocks;
  `);
  resetSealedSchemaProbe();
}, 300_000);
afterAll(async () => { await h.db?.close(); });

describe("sealed request: visitor -> worker -> server -> Neon -> host Studio", () => {
  let doc: Ops["bookingKey.ensure"]["res"]["doc"];
  let request: ReturnType<typeof parseInquiryRequest>;

  it("1. host device creates its booking key in the worker and publishes it; every seed and secret key is wiped", async () => {
    h.caller = HOST;
    const { handle } = await call("masterKey.generate", {});
    await call("masterKey.commitPending", { handle, userId: HOST });
    drain(h.secrets);
    doc = (await call("bookingKey.ensure", { userId: HOST, existing: null })).doc;
    expect(allWiped(drain(h.secrets))).toBe(true);
    expect(await publishOwnBookingKey(doc, false)).toEqual({ ok: true, kid: doc.kid });
  });

  it("2. visitor seals the request in the worker (RVE1 bkh, BLAKE3 Hashcash) and the worker wipes what it was handed", async () => {
    h.caller = null;
    const key = await profileBookingKey("ann");
    if (!key.ok) throw new Error(key.reason);
    const publicKey = b64uDecode(key.publicKey)!;
    drain(h.secrets);
    const sealed = await call("booking.seal", { hosts: [{ ref: key.ref, publicKey }], payload: PAYLOAD, pow: { purpose: "inquiry" } });
    expect(publicKey.every((b) => b === 0)).toBe(true);
    expect(allWiped(drain(h.secrets))).toBe(true);
    const envelope = sealed.hosts[0]!.envelope;
    expect(new TextDecoder().decode(envelope.subarray(0, 4))).toBe("RVE1");
    for (const needle of ["Ada", "example.com", "allergie"]) expect(new TextDecoder("latin1").decode(envelope)).not.toContain(needle);
    request = parseInquiryRequest({
      handle: "ann", preferredDate: day, preferredTime: "10:30",
      sealed: { pid: sealed.payloadId, ref: key.ref, envelope: b64uEncode(envelope) },
      pow: sealed.pow!,
    });
  });

  it("3. server refuses a forged or stale proof without touching the database", async () => {
    const before = h.dbCalls;
    const flipped = request.pow.nonce.replace(/^./, (c) => (c === "0" ? "1" : "0"));
    expect(await createSealedInquiry({ ...request, pow: { ...request.pow, nonce: flipped } })).toEqual({ ok: false, reason: "pow_invalid" });
    const env = b64uDecode(request.sealed.envelope)!;
    const stale = solveSealedPow("inquiry", request.sealed.pid, [{ ref: request.sealed.ref, envelope: env }], Date.now() - 6 * 3600_000);
    expect(await createSealedInquiry({ ...request, pow: stale })).toEqual({ ok: false, reason: "pow_stale" });
    expect(h.dbCalls).toBe(before);
  });

  it("4. server accepts the valid proof, writes only ciphertext through rout_inquiry_create_sealed, and wipes its copies", async () => {
    drain(h.serverBuffers);
    expect(await createSealedInquiry(request)).toEqual({ ok: true, pid: request.sealed.pid });
    const kept = drain(h.serverBuffers);
    console.log("DBG", kept.map((b) => [b.length, b.some((x) => x !== 0)]));
    expect(allWiped(kept)).toBe(true);
    await h.db!.exec("reset role");
    const rows = (await h.db!.query<Record<string, unknown>>("select * from public.inquiries")).rows;
    expect(rows).toHaveLength(1);
    expect(rows[0]!["encrypted_rve1_payload"]).toBe(request.sealed.envelope);
    expect(rows[0]!["pow_nonce"]).toBe(request.pow.nonce);
    expect(JSON.stringify(rows[0])).not.toMatch(/Ada|example\.com|allergie/);
  });

  it("5. the same proof cannot be used twice", async () => {
    h.caller = null;
    expect(await createSealedInquiry(request)).toEqual({ ok: false, reason: "invalid" });
    await h.db!.exec("reset role");
    expect((await h.db!.query("select 1 from public.inquiries")).rows).toHaveLength(1);
  });

  it("6. another member sees nothing; the host reads the row under RLS and opens it on the device", async () => {
    h.caller = OTHER;
    expect((await listHostInquiries(OTHER, null)).filter((i) => i.sealed)).toEqual([]);
    expect((await listHostInquiries(HOST, null)).filter((i) => i.sealed)).toEqual([]);

    h.caller = HOST;
    const list = (await listHostInquiries(HOST, null)).filter((i) => i.sealed);
    expect(list).toHaveLength(1);
    const own = await readOwnBookingKey(HOST);
    expect(own).toEqual(doc);
    drain(h.secrets);
    const opened = await call("bookingKey.open", {
      userId: HOST, doc: own!, items: [{ payloadId: list[0]!.sealed!.pid, envelope: b64uDecode(list[0]!.sealed!.envelope)! }],
    });
    expect(opened.payloads).toEqual([PAYLOAD]);
    expect(allWiped(drain(h.secrets))).toBe(true);
  });

  it("7. another member's device cannot open the host's copy", async () => {
    const { handle } = await call("masterKey.generate", {});
    await call("masterKey.commitPending", { handle, userId: OTHER });
    const r = await runEnclaveOp("bookingKey.open", { userId: OTHER, doc, items: [{ payloadId: request.sealed.pid, envelope: b64uDecode(request.sealed.envelope)! }] });
    expect(r.ok ? "ok" : r.code).toBe("key_mismatch");
  });
});
