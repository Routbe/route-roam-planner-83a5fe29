# Z3 certification — 0278_zk_inquiries_and_rve1_payloads.sql

Run: 2026-11-15T18:57:40.682Z · offline PGlite replay of db/ (0278 included) · Neon not contacted

- Obligations: 1225, Z3 checks: 547
- proven (unsat): 1185 · declassified (reviewed): 10 · service boundary: 30 · unproven: 0
- SECURITY DEFINER without pg_catalog, pg_temp: 0 of 432
- New findings: 0 · unused model entries: 0
- public.booking_host_keys: 5 of 5 obligations proven
- public.inquiries: 5 of 5 obligations proven
- public.booking_payloads: 5 of 5 obligations proven

**Result: CERTIFIED**


0278 was applied on Neon on 2026-11-15 (owner's GO, scripts/migration-rollout.ts, sha256 508850f1…) and lives in db/.
The Z3 model covers row visibility under the policies; table write grants are closed by db/0279 (rout_app SELECT only).
