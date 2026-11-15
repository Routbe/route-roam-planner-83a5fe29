// @vitest-environment node
/**
 * db/0280 on an offline replay of db/ without it. The Neon state before 0280 is recreated: both
 * functions with their line breaks collapsed (same tokens) and the Neon-managed column present.
 * 0280 must restore the exact replay text, keep behaviour and grants, and leave the column alone;
 * the social-grid trigger must still index cards under its pinned search_path.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { PGlite } from "@electric-sql/pglite";
import { applyReleased, replayDb } from "../../scripts/formal-rls/replay";

const FILE = "0280_zero_drift_reconciliation.sql";
const POW = "public.rout_pow_spend(text, text, timestamp with time zone)";
let db: PGlite;
let replayText: Record<string, string>;
const src = async (name: string) =>
  (await db.query<{ s: string }>("select prosrc as s from pg_proc where proname = $1", [name])).rows[0]!.s;
const can = async (role: string, fn: string) =>
  (await db.query<{ ok: boolean }>("select has_function_privilege($1, $2, 'execute') as ok", [role, fn])).rows[0]!.ok;

beforeAll(async () => {
  db = await replayDb((f) => f !== FILE);
  replayText = { pow: await src("rout_pow_spend"), grid: await src("sync_social_grid_draft") };
  // Neon before 0280: same bodies on one line, and Neon Auth's own extra column.
  for (const name of ["rout_pow_spend", "sync_social_grid_draft"]) {
    const def = (await db.query<{ d: string }>("select pg_get_functiondef(oid) as d from pg_proc where proname = $1", [name])).rows[0]!.d;
    const [head, body] = def.split("AS $function$");
    await db.exec(`${head}AS $function$${body!.replace(/\$function\$\s*$/, "").replace(/\s*\n\s*/g, " ")}$function$`);
  }
  await db.exec("alter table neon_auth.project_config add column auth_logs_export_enabled boolean default false");
}, 300_000);
afterAll(async () => { await db?.close(); });

describe("db/0280", () => {
  it("restores the replay text of both functions without changing grants", async () => {
    expect(await src("rout_pow_spend")).not.toBe(replayText.pow);
    await applyReleased(db, FILE);
    expect(await src("rout_pow_spend")).toBe(replayText.pow);
    expect(await src("sync_social_grid_draft")).toBe(replayText.grid);
    expect(await can("rout_app", POW)).toBe(true);
    const publicAcl = await db.query("select 1 from pg_proc p, aclexplode(p.proacl) a where p.oid = $1::regprocedure and a.grantee = 0", [POW]);
    expect(publicAcl.rows).toHaveLength(0);
    expect(await can("rout_app", "public.sync_social_grid_draft()")).toBe(true);
  });

  it("still indexes social-grid cards from a profile draft under search_path pg_catalog, pg_temp", async () => {
    const cfg = (await db.query<{ c: string[] }>("select proconfig as c from pg_proc where proname = 'sync_social_grid_draft'")).rows[0]!.c;
    expect(cfg).toEqual(["search_path=pg_catalog, pg_temp"]);
    const u = "00000000-0000-4000-8000-000000000280";
    await db.query("insert into public.users (id, email) values ($1, 'grid@example.org')", [u]);
    await db.query("insert into public.profiles (id, username) values ($1, 'grid0280')", [u]);
    const block = (items: unknown[]) => JSON.stringify({ blocks: [{ id: "b1", kind: "social_grid", value: JSON.stringify({ items }) }] });
    await db.query("insert into public.profile_drafts (user_id, space, payload) values ($1, 'verified', $2::jsonb)",
      [u, block([{ id: "i1", mediaUrl: "https://e.org/1.jpg", platform: "instagram" }, { id: "i2", mediaUrl: "https://e.org/2.jpg", platform: "nope" }])]);
    const rows = async () => (await db.query<{ source_item_id: string; platform: string; position: number }>(
      "select source_item_id, platform, position from public.social_grid_items where user_id = $1 order by position", [u])).rows;
    expect(await rows()).toEqual([
      { source_item_id: "i1", platform: "instagram", position: 0 },
      { source_item_id: "i2", platform: "custom", position: 1 },
    ]);
    await db.query("update public.profile_drafts set payload = $2::jsonb where user_id = $1", [u, block([{ id: "i2", mediaUrl: "https://e.org/2.jpg" }])]);
    expect(await rows()).toEqual([{ source_item_id: "i2", platform: "custom", position: 0 }]);
  });

  it("keeps a proof-of-work hash single-use", async () => {
    const spend = async () =>
      (await db.query<{ ok: boolean }>("select public.rout_pow_spend('h-0280', 'test', now() + interval '5 minutes') as ok")).rows[0]!.ok;
    expect(await spend()).toBe(true);
    expect(await spend()).toBe(false);
  });

  it("leaves an existing Neon-managed column untouched and is re-runnable", async () => {
    await expect(applyReleased(db, FILE)).resolves.not.toThrow();
    const cols = await db.query("select 1 from information_schema.columns where table_schema = 'neon_auth' and table_name = 'project_config' and column_name = 'auth_logs_export_enabled'");
    expect(cols.rows).toHaveLength(1);
  });
});
