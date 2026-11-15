// @vitest-environment node
/**
 * db/0279 on an offline replay of db/ without it: Neon's default privileges are simulated by granting
 * rout_app write rights on the three sealed tables, then 0279 must leave rout_app with SELECT only.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { applyReleased, replayDb } from "../../scripts/formal-rls/replay";

const TABLES = ["public.booking_host_keys", "public.inquiries", "public.booking_payloads"];
let db: PGlite;
beforeAll(async () => {
  db = await replayDb((f) => !f.startsWith("0279_"));
  await db.exec(`grant insert, update, delete on ${TABLES.join(", ")} to rout_app`);
}, 300_000);
afterAll(async () => { await db?.close(); });

const can = async (t: string, p: string) =>
  (await db.query<{ ok: boolean }>("select has_table_privilege('rout_app', $1, $2) as ok", [t, p])).rows[0]!.ok;

describe("db/0279", () => {
  it("removes every write privilege of rout_app and keeps SELECT", async () => {
    expect(await can(TABLES[0]!, "insert")).toBe(true);
    await applyReleased(db, "0279_sealed_tables_read_only_grants.sql");
    for (const t of TABLES) {
      expect(await can(t, "select")).toBe(true);
      for (const p of ["insert", "update", "delete", "truncate", "references", "trigger"]) expect(await can(t, p)).toBe(false);
    }
  });
});
