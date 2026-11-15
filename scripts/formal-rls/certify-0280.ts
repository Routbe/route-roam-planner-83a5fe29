/**
 * Z3 certification of the schema at level 0280 (zero-drift reconciliation after 0278/0279).
 * Default: offline PGlite replay of db/. With --url-env <VAR> the catalog is read from that live
 * database instead (catalog SELECTs only, nothing written), so the proof runs on exactly what
 * Neon serves. The verifier encodes every rout_app policy to SMT; "proven" means Z3 returned unsat
 * for "a row of tenant B is visible/writable for tenant A".
 * Certified = no finding outside KNOWN_OPEN, zero unproven obligations, zero unused model
 * entries, every SECURITY DEFINER on pg_catalog, pg_temp, each sealed-payload table covered by at
 * least one proven obligation, and (live mode) the live catalog equal to db/schema.snapshot.json.
 *
 *   bun scripts/formal-rls/certify-0280.ts [--url-env OWNER_DATABASE_URL] [--smt-out dir]
 * Writes docs/rls-0280-certification.md.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { diffCatalogs, readCatalog, type Catalog } from "../schema-catalog";
import { Verifier } from "../formal-rls-verifier";
import { KNOWN_OPEN } from "./tenant-model";
import { replayDb, ROOT } from "./replay";

const TABLES = ["public.booking_host_keys", "public.inquiries", "public.booking_payloads"];
const args = process.argv.slice(2);
const smtOut = args.includes("--smt-out") ? args[args.indexOf("--smt-out") + 1] : undefined;
const urlEnv = args.includes("--url-env") ? args[args.indexOf("--url-env") + 1] : undefined;
const VIEW_OPTS = `select n.nspname || '.' || c.relname as k, c.reloptions as o from pg_class c join pg_namespace n on n.oid = c.relnamespace where c.relkind = 'v'`;

let q: (s: string) => Promise<Record<string, unknown>[]>;
let close: () => Promise<void>;
if (urlEnv) {
  const url = process.env[urlEnv];
  if (!url) throw new Error(`${urlEnv} is not set`);
  const { Pool } = await import("@neondatabase/serverless");
  const pool = new Pool({ connectionString: url });
  q = async (s) => {
    if (!/^\s*(with|select)\b/i.test(s)) throw new Error("refused: catalog reads only");
    return (await pool.query(s)).rows;
  };
  close = () => pool.end();
} else {
  const db = await replayDb();
  q = async (s) => (await db.query<Record<string, unknown>>(s)).rows;
  close = () => db.close();
}
const cat = await readCatalog(q);
const opts = (await q(VIEW_OPTS)) as { k: string; o: string[] | null }[];
await close();
const report = await new Verifier(cat, Object.fromEntries(opts.map((r) => [r.k, r.o ?? []]))).run({ smtOut });

const committed = JSON.parse(readFileSync(join(ROOT, "db", "schema.snapshot.json"), "utf8")) as Catalog;
const drift = urlEnv ? diffCatalogs(committed, cat) : [];
const open = new Set(KNOWN_OPEN.map((k) => k.id));
const fresh = report.findings.filter((f) => !open.has(f.id));
const count = (s: string) => report.obligations.filter((o) => o.outcome.status === s).length;
const coverage = TABLES.map((t) => {
  const name = t.split(".")[1]!;
  const mine = report.obligations.filter((o) => JSON.stringify(o).includes(name));
  return { table: t, obligations: mine.length, proven: mine.filter((o) => o.outcome.status === "proven").length };
});
const uncovered = coverage.filter((c) => c.proven === 0);
const certified = fresh.length === 0 && count("unproven") === 0 && report.unusedModelEntries.length === 0
  && report.searchPath.findings.length === 0 && uncovered.length === 0 && drift.length === 0;

const md = [
  "# Z3 certification — schema level 0280",
  "",
  `Run: ${new Date().toISOString()} · ${urlEnv ? `live catalog via ${urlEnv} (read-only)` : "offline PGlite replay of db/ · Neon not contacted"}`,
  "",
  `- Obligations: ${report.obligations.length}, Z3 checks: ${report.smtChecks}`,
  `- proven (unsat): ${count("proven")} · declassified (reviewed): ${count("declassified")} · service boundary: ${count("service_boundary")} · unproven: ${count("unproven")}`,
  `- SECURITY DEFINER without pg_catalog, pg_temp: ${report.searchPath.findings.length} of ${report.searchPath.definers}`,
  `- New findings: ${fresh.length} · unused model entries: ${report.unusedModelEntries.length}`,
  ...(urlEnv ? [`- Live catalog vs db/schema.snapshot.json: ${drift.length} differences`] : []),
  ...coverage.map((c) => `- ${c.table}: ${c.proven} of ${c.obligations} obligations proven`),
  "",
  `**Result: ${certified ? "CERTIFIED" : "NOT CERTIFIED"}**`,
  "",
  ...fresh.map((f) => `- ${f.id}: ${f.detail}`),
  ...uncovered.map((c) => `- ${c.table}: no proven obligation`),
  ...drift.map((d) => `- drift: ${d}`),
  "",
  "The Z3 model covers row visibility under the policies; table write grants on the sealed tables are closed by db/0279 (rout_app SELECT only).",
];
writeFileSync(join(ROOT, "docs", "rls-0280-certification.md"), md.join("\n") + "\n");
console.log(md.slice(2, 16).join("\n"));
process.exitCode = certified ? 0 : 1;
