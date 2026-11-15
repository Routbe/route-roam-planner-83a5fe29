/**
 * Z3 certification of db-pending/0278 (EXPAND: booking_host_keys, inquiries, booking_payloads).
 * Replays db/ on PGlite, applies 0278 from db-pending/, reads the catalog and runs the formal RLS
 * verifier: every rout_app policy is encoded to SMT and "proven" means Z3 returned unsat for
 * "a row of tenant B is visible/writable for tenant A".
 * Certified = no finding outside KNOWN_OPEN, zero unproven obligations, zero unused model
 * entries, every SECURITY DEFINER on pg_catalog, pg_temp, and each new table covered by at
 * least one proven obligation.
 *
 *   bun scripts/formal-rls/certify-0278.ts [--smt-out dir]
 * Writes docs/rls-0278-certification.md. Read-only on Neon: it never connects to it.
 */
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readCatalog } from "../schema-catalog";
import { Verifier } from "../formal-rls-verifier";
import { KNOWN_OPEN } from "./tenant-model";
import { applyPending, replayDb, ROOT } from "./replay";

const FILE = "0278_zk_inquiries_and_rve1_payloads.sql";
const NEW_TABLES = ["public.booking_host_keys", "public.inquiries", "public.booking_payloads"];
const args = process.argv.slice(2);
const smtOut = args.includes("--smt-out") ? args[args.indexOf("--smt-out") + 1] : undefined;

const db = await replayDb();
if (!existsSync(join(ROOT, "db", FILE))) await applyPending(db, FILE);
const cat = await readCatalog(async (q) => (await db.query<Record<string, unknown>>(q)).rows);
const opts = (await db.query<{ k: string; o: string[] | null }>(`select n.nspname || '.' || c.relname as k, c.reloptions as o from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind = 'v'`)).rows;
const report = await new Verifier(cat, Object.fromEntries(opts.map((r) => [r.k, r.o ?? []]))).run({ smtOut });
await db.close();

const open = new Set(KNOWN_OPEN.map((k) => k.id));
const fresh = report.findings.filter((f) => !open.has(f.id));
const count = (s: string) => report.obligations.filter((o) => o.outcome.status === s).length;
const text = (o: unknown) => JSON.stringify(o);
const coverage = NEW_TABLES.map((t) => {
  const name = t.split(".")[1]!;
  const mine = report.obligations.filter((o) => text(o).includes(name));
  return { table: t, obligations: mine.length, proven: mine.filter((o) => o.outcome.status === "proven").length };
});
const uncovered = coverage.filter((c) => c.proven === 0);
const certified = fresh.length === 0 && count("unproven") === 0 && report.unusedModelEntries.length === 0
  && report.searchPath.findings.length === 0 && uncovered.length === 0;

const md = [
  `# Z3 certification — ${FILE}`,
  "",
  `Run: ${new Date().toISOString()} · offline PGlite replay of db/${existsSync(join(ROOT, "db", FILE)) ? " (0278 included)" : " + db-pending/0278"} · Neon not contacted`,
  "",
  `- Obligations: ${report.obligations.length}, Z3 checks: ${report.smtChecks}`,
  `- proven (unsat): ${count("proven")} · declassified (reviewed): ${count("declassified")} · service boundary: ${count("service_boundary")} · unproven: ${count("unproven")}`,
  `- SECURITY DEFINER without pg_catalog, pg_temp: ${report.searchPath.findings.length} of ${report.searchPath.definers}`,
  `- New findings: ${fresh.length} · unused model entries: ${report.unusedModelEntries.length}`,
  ...coverage.map((c) => `- ${c.table}: ${c.proven} of ${c.obligations} obligations proven`),
  "",
  `**Result: ${certified ? "CERTIFIED" : "NOT CERTIFIED"}**`,
  "",
  ...fresh.map((f) => `- ${f.id}: ${f.detail}`),
  ...uncovered.map((c) => `- ${c.table}: no proven obligation`),
  "",
  "Certification is a precondition for 0278, not a GO: 0278 stays in db-pending/ until the owner gives a",
  "separate GO; the code using it fails closed (\"unavailable\") until the migration is applied.",
];
writeFileSync(join(ROOT, "docs", "rls-0278-certification.md"), md.join("\n") + "\n");
console.log(md.slice(4, 14).join("\n"));
process.exitCode = certified ? 0 : 1;
