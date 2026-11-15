# Z3 certification — db-pending/0278_zk_inquiries_and_rve1_payloads.sql

Run: 2026-11-15T18:35:34.451Z · offline PGlite replay of db/ + db-pending/0278 · Neon not contacted

- Obligations: 1225, Z3 checks: 547
- proven (unsat): 1185 · declassified (reviewed): 10 · service boundary: 30 · unproven: 0
- SECURITY DEFINER without pg_catalog, pg_temp: 0 of 432
- New findings: 0 · unused model entries: 0
- public.booking_host_keys: 5 of 5 obligations proven
- public.inquiries: 5 of 5 obligations proven
- public.booking_payloads: 5 of 5 obligations proven

**Result: CERTIFIED**


Certification is a precondition for 0278, not a GO: 0278 stays in db-pending/ until the owner gives a
separate GO; the code using it fails closed ("unavailable") until the migration is applied.
