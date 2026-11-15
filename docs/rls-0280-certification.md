# Z3 certification — schema level 0280

Run: 2026-11-15T19:12:04.497Z · live catalog via OWNER_DATABASE_URL (read-only)

- Obligations: 1225, Z3 checks: 547
- proven (unsat): 1185 · declassified (reviewed): 10 · service boundary: 30 · unproven: 0
- SECURITY DEFINER without pg_catalog, pg_temp: 0 of 432
- New findings: 0 · unused model entries: 0
- Live catalog vs db/schema.snapshot.json: 0 differences
- public.booking_host_keys: 5 of 5 obligations proven
- public.inquiries: 5 of 5 obligations proven
- public.booking_payloads: 5 of 5 obligations proven

**Result: CERTIFIED**


The Z3 model covers row visibility under the policies; table write grants on the sealed tables are closed by db/0279 (rout_app SELECT only).
