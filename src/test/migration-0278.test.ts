// @vitest-environment node
/**
 * Integration test of db/0278 on an offline replay of db/ (PGlite; Neon is never contacted).
 * Exercises the definer entry points as rout_app with the caller in rout.current_user_id, the RLS
 * isolation between hosts, replay protection on the BLAKE3 payload hash, the epoch window, and the
 * rollback file (db-pending/). 0278 was applied on Neon on 2026-11-15 and is part of the replay.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { blake3 } from "@noble/hashes/blake3.js";
import { applyReleased, replayDb, ROOT } from "../../scripts/formal-rls/replay";
import { AUDIT_ROLES, POLICY_GRANT_AUDIT_SQL } from "../../scripts/formal-rls/policy-grant-audit";
import { hostBookingKeys, sealBookingPayload } from "@/lib/crypto-enclave/booking-seal";
import { epochBucketAt, solveSealedPow } from "@/lib/crypto-enclave/sealed-pow";
import { b64uEncode, hostRefOf } from "@/lib/booking-engine/sealed-booking";

const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const ET = "11111111-1111-4111-8111-111111111111";
const keyA = hostBookingKeys(new Uint8Array(32).fill(7));
const keyB = hostBookingKeys(new Uint8Array(32).fill(8));
const refA = hostRefOf(keyA.publicKey);
const refB = hostRefOf(keyB.publicKey);
const seal = "v1." + "A".repeat(16) + "." + "B".repeat(64);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const day = new Date(Date.now() + 3 * 86400000).toISOString().slice(0, 10);
type J = Record<string, unknown>;

let db: PGlite;
const as = async (user: string | null) => {
  await db.exec("reset role");
  await db.query("select set_config('rout.current_user_id', $1, false)", [user ?? ""]);
  await db.exec("set role rout_app");
};
const one = async <T = J>(q: string, p: unknown[] = []) => (await db.query<{ r: T }>(q, p)).rows[0]!.r;
function sealedFor(pid: string, ref: string, pk: Uint8Array, purpose: "booking" | "inquiry") {
  const env = sealBookingPayload({ hostUserId: ref, payloadId: pid, payload: { name: "Ada", email: "ada@example.com" }, hostPublicKey: pk }).host;
  const pow = solveSealedPow(purpose, pid, [{ ref, envelope: env }], Date.now());
  return { envelope: b64uEncode(env), hash: hex(blake3(env)), ...pow };
}
const publish = (ref: string, k: ReturnType<typeof hostBookingKeys>, replace = false) =>
  one("select public.rout_booking_host_key_publish($1::uuid, $2, $3, $4, 'wk_1', $5) as r", [ref, b64uEncode(k.kid), b64uEncode(k.publicKey), seal, replace]);
const inquiry = (pid: string, s: ReturnType<typeof sealedFor>, ref = refA, epoch = s.epoch) =>
  one("select public.rout_inquiry_create_sealed($1::uuid, $2::uuid, $3::uuid, $4::date, '10:30', 30, 'Intro', $5, decode($6, 'hex'), $7, $8) as r",
    [A, pid, ref, day, s.envelope, s.hash, s.nonce, epoch]);
const book = (pid: string, copies: unknown[], nonce: string, epoch: number, start = `${day}T10:00:00Z`) =>
  one("select public.rout_booking_create_sealed($1::uuid, $2::timestamptz, 'Europe/Brussels', $3::uuid, $4::jsonb, $5, $6, null, null) as r",
    [ET, start, pid, JSON.stringify(copies), nonce, epoch]);

beforeAll(async () => {
  db = await replayDb();
  await db.exec(`
    insert into public.users (id, email) values ('${A}', 'a@example.org'), ('${B}', 'b@example.org');
    insert into public.profiles (id, username, blocks) values ('${A}', 'ann', '[{"kind":"booking_request"}]'), ('${B}', 'bob', '[]')
      on conflict (id) do update set username = excluded.username, blocks = excluded.blocks;
    insert into public.booking_event_types (id, user_id, slug, title, duration_minutes, minimum_notice_hours) values ('${ET}', '${A}', 'intro', 'Intro', 30, 0);
    insert into public.booking_event_type_hosts (event_type_id, user_id, priority) values ('${ET}', '${A}', 0);
    insert into public.availability_cache (user_id, day, free_bits) values ('${A}', '${day}', repeat('1', 96)::bit(96));
  `);
}, 300_000);
afterAll(async () => { await db?.close(); });

describe("db/0278 on a replay of db/", () => {
  it("every audited role can execute each helper the new policies need; internal helpers stay closed to rout_app", async () => {
    await db.exec("reset role");
    expect((await db.query(POLICY_GRANT_AUDIT_SQL, [AUDIT_ROLES as unknown as string[]])).rows).toEqual([]);
    const can = async (fn: string) => (await db.query<{ ok: boolean }>("select has_function_privilege('rout_app', $1, 'execute') as ok", [fn])).rows[0]!.ok;
    expect(await can("public.rout_sealed_envelope_ok(text)")).toBe(false);
    expect(await can("public.rout_sealed_epoch_ok(integer)")).toBe(false);
    expect(await can("public.rout_booking_create_sealed(uuid, timestamptz, text, uuid, jsonb, text, integer, uuid, text)")).toBe(true);
    const pub = await db.query<{ ok: boolean }>("select has_function_privilege('public', 'public.rout_inquiry_create_sealed(uuid, uuid, uuid, date, text, integer, text, text, bytea, text, integer)', 'execute') as ok");
    expect(pub.rows[0]!.ok).toBe(false);
  });

  it("rout_app can read the new tables but never write them directly", async () => {
    await as(A);
    await expect(db.query(`insert into public.booking_host_keys (host_user_id, host_ref, kid, public_key, sealed_seed, key_id) values ('${A}', '${refA}', 'x', 'x', 'x', 'x')`)).rejects.toThrow(/permission denied/);
    await expect(db.query(`delete from public.inquiries`)).rejects.toThrow(/permission denied/);
    await expect(db.query(`update public.booking_payloads set epoch_bucket = 1`)).rejects.toThrow(/permission denied/);
  });

  it("a host publishes its own key; a different key replaces it only by explicit choice", async () => {
    await as(null);
    expect(await publish(refA, keyA)).toEqual({ ok: false, reason: "input" });
    await as(A);
    expect(await publish(refA, keyA)).toEqual({ ok: true, kid: b64uEncode(keyA.kid) });
    expect(await publish(refB, keyB)).toEqual({ ok: false, reason: "exists" });
    await as(B);
    expect(await publish(refB, keyB)).toEqual({ ok: true, kid: b64uEncode(keyB.kid) });
    // Another member can read neither key row through RLS.
    expect((await db.query(`select 1 from public.booking_host_keys where host_user_id = '${A}'`)).rows).toHaveLength(0);
    await as(A);
    expect((await db.query(`select host_ref from public.booking_host_keys`)).rows).toEqual([{ host_ref: refA }]);
  });

  it("guests see only references and public keys, never user ids", async () => {
    await as(null);
    const keys = await one<J>("select public.rout_booking_event_host_keys($1::uuid) as r", [ET]);
    expect(keys).toEqual({ hosts: 1, keys: [{ ref: refA, kid: b64uEncode(keyA.kid), publicKey: b64uEncode(keyA.publicKey) }] });
    expect(JSON.stringify(keys)).not.toContain(A);
    expect(await one("select public.rout_booking_profile_host_key($1::uuid) as r", [A])).toMatchObject({ ref: refA });
    expect(await one("select public.rout_booking_profile_host_key($1::uuid) as r", [B])).toBeNull();
  });

  it("stores a sealed inquiry once; a replayed proof, a stale epoch or a foreign reference is refused", async () => {
    await as(null);
    const pid = "22222222-2222-4222-8222-222222222222";
    const s = sealedFor(pid, refA, keyA.publicKey, "inquiry");
    expect(await inquiry(pid, s)).toMatchObject({ ok: true });
    expect(await inquiry("33333333-3333-4333-8333-333333333333", s)).toEqual({ ok: false, reason: "duplicate" });
    const s2 = sealedFor("44444444-4444-4444-8444-444444444444", refA, keyA.publicKey, "inquiry");
    expect(await inquiry("44444444-4444-4444-8444-444444444444", s2, refA, epochBucketAt(Date.now()) - 2)).toEqual({ ok: false, reason: "pow_stale" });
    expect(await inquiry("44444444-4444-4444-8444-444444444444", s2, refB)).toEqual({ ok: false, reason: "invalid" });
    expect(await inquiry("44444444-4444-4444-8444-444444444444", { ...s2, envelope: "UlZFMQEF" + "A".repeat(100) })).toEqual({ ok: false, reason: "invalid" });
  });

  it("only the host reads and resolves its own inquiries", async () => {
    await as(B);
    expect((await db.query("select 1 from public.inquiries")).rows).toHaveLength(0);
    const id = (await (async () => { await as(A); return db.query<{ id: string }>("select id from public.inquiries"); })()).rows[0]!.id;
    await as(B);
    expect(await one("select public.rout_inquiry_resolve($1::uuid, 'accept') as r", [id])).toBe(false);
    await as(A);
    expect(await one("select public.rout_inquiry_resolve($1::uuid, 'accept') as r", [id])).toBe(true);
    expect(await one("select public.rout_inquiry_resolve($1::uuid, 'decline') as r", [id])).toBe(false);
  });

  it("a sealed booking writes placeholders in bookings and the host copy in booking_payloads", async () => {
    await as(null);
    const pid = "55555555-5555-4555-8555-555555555555";
    const s = sealedFor(pid, refA, keyA.publicKey, "booking");
    expect(await book(pid, [{ ref: refA, envelope: s.envelope, hash: s.hash }], s.nonce, epochBucketAt(Date.now()) + 2)).toEqual({ ok: false, reason: "pow_stale" });
    expect(await book(pid, [{ ref: refB, envelope: s.envelope, hash: s.hash }], s.nonce, s.epoch)).toEqual({ ok: false, reason: "host_key_missing" });
    expect(await book(pid, [{ ref: refA, envelope: "plain text", hash: s.hash }], s.nonce, s.epoch)).toEqual({ ok: false, reason: "invalid_intake" });
    const r = await book(pid, [{ ref: refA, envelope: s.envelope, hash: s.hash }], s.nonce, s.epoch);
    expect(r).toMatchObject({ ok: true });
    const bid = (r["bookingIds"] as string[])[0]!;
    await db.exec("reset role");
    const row = (await db.query<J>(`select guest_name, guest_email, intake_answers from public.bookings where id = '${bid}'`)).rows[0]!;
    expect(row).toEqual({ guest_name: "RVE1", guest_email: `${pid}@sealed.invalid`, intake_answers: { v: 3, pid } });
    await as(B);
    expect((await db.query("select 1 from public.booking_payloads")).rows).toHaveLength(0);
    await as(A);
    expect((await db.query<J>("select host_ref, encrypted_rve1_payload from public.booking_payloads")).rows).toEqual([{ host_ref: refA, encrypted_rve1_payload: s.envelope }]);
    // Same ciphertext again (replayed proof) is refused by the unique payload hash; the booking rolls back.
    await as(null);
    await expect(book("66666666-6666-4666-8666-666666666666", [{ ref: refA, envelope: s.envelope, hash: s.hash }], s.nonce, s.epoch, `${day}T11:00:00Z`)).rejects.toThrow(/duplicate key|unique/);
    await db.exec("reset role");
    expect((await db.query("select 1 from public.bookings where guest_email like '66666666%'")).rows).toHaveLength(0);
  });

  it("the rollback refuses while sealed rows exist, then removes 0278 completely, and 0278 applies again", async () => {
    await db.exec("reset role");
    const body = readFileSync(join(ROOT, "db-pending", "0278_zk_inquiries_and_rve1_payloads_rollback.sql"), "utf8");
    // While sealed ciphertext exists the rollback refuses: it would destroy the only copy.
    await expect(db.exec(`begin;\n${body}\n;commit;`)).rejects.toThrow(/rollback refused/);
    await db.exec("rollback");
    await db.exec("delete from public.booking_payloads; delete from public.inquiries; delete from public.booking_host_keys; delete from public.bookings where intake_answers->>'v' = '3'");
    await db.exec(`begin;\n${body}\n;commit;`);
    const left = await db.query<{ n: string }>(`select coalesce(to_regclass('public.inquiries')::text, '') ||
      coalesce(to_regclass('public.booking_payloads')::text, '') || coalesce(to_regclass('public.booking_host_keys')::text, '') as n`);
    expect(left.rows[0]!.n).toBe("");
    expect((await db.query("select 1 from pg_proc where proname like 'rout_inquiry_%' or proname like 'rout_booking_%sealed%' or proname = 'rout_booking_host_key_publish'")).rows).toHaveLength(0);
    await applyReleased(db, "0278_zk_inquiries_and_rve1_payloads.sql");
  });
});
