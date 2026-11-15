# Held-back migrations

CONTRACT steps that remove legacy access. They stay out of `db/` (every file
there is replayed by the runners) until the deployed app uses the matching
EXPAND functions. Move a file into `db/` only when production runs that code
(the public health probe reports `schema` at or above the EXPAND number).


Applied and moved into `db/`: 0230, 0231, 0233, 0235, 0237 (production reported 0236).
- 0239 and 0241 applied (Nov 2026); no legacy rout_server access remains.
- 0262 applied on Neon (2026-11-13) and moved into `db/`.
- 0263 and 0264 applied on Neon (2026-11-13, production reported 0263); 0264 moved into `db/`. 

- 0265_booking_ledger.sql: held back (EXPAND, not yet applied on Neon); greatest/least unqualified. Moves to db/ only after the owner's GO; CODE_SCHEMA_LEVEL is never lowered (it stays at the highest db/ file, currently 0277), and a single-file rollout names 0264_* as its predecessor (`--after=`).
- 0266_recovery_card_factor.sql: applied on Neon (2026-11-13 21:45) and moved into `db/`; CODE_SCHEMA_LEVEL is 0266.
- 0267_card_recovery_factor_tap.sql: applied on Neon (2026-11-14 12:12 UTC, owner's GO) and moved into `db/`; CODE_SCHEMA_LEVEL is 0267. Its rollback stays here (`0267_card_recovery_factor_tap_rollback.sql`, refuses while recovery_factor grants exist).
- 0272_dynamic_recovery_v4.sql: applied on Neon (2026-11-14 18:18 UTC, owner's GO) and moved into `db/`; CODE_SCHEMA_LEVEL is 0272. Its rollback stays here (`0272_dynamic_recovery_v4_rollback.sql`, refuses once a ceremony or recovery_v4 audit entry exists).
- 0268/0269 (recovery v3 drafts, never applied): moved to `db-archive/` (owner, 2026-11-14); recovery v4 (0272) replaces them.
- 0273_anonymous_booking_engine.sql (Stap 7e/7f): applied on Neon (2026-11-15 07:39 UTC, owner's GO) through `scripts/migration-rollout.ts` and moved into `db/`; CODE_SCHEMA_LEVEL is 0273. Its rollback stays here (`0273_anonymous_booking_engine_rollback.sql`, idempotent, refuses once any anon_* table holds a row or an anon_* audit entry exists).
- 0274_multi_device_host_keys.sql (Stap 7g, EXPAND): applied on Neon (2026-11-15 08:35 UTC, owner's GO) through `scripts/migration-rollout.ts` and moved into `db/`; CODE_SCHEMA_LEVEL is 0274. Its rollback stays here (`0274_multi_device_host_keys_rollback.sql`, idempotent, refuses once a device, endorsement or 0274 audit entry exists).
- 0275 and 0276 applied on Neon (2026-11-15) and moved into `db/`; CODE_SCHEMA_LEVEL is 0276. Their rollbacks stay here.
- 0277_tenant_contract_and_merge_fix.sql (CONTRACT + account-merge grants): moved into `db/` after production reported 0276, the live read-only pre-check (`bun scripts/tenant-backfill.ts --gateway`) gave 0 deviations, `scripts/formal-rls/certify-0277.ts` printed CERTIFIED and the owner gave GO (2026-11-15); CODE_SCHEMA_LEVEL is 0277. Its rollback stays here (`0277_tenant_contract_and_merge_fix_rollback.sql`).

- Correction (2026-11-15): the header of `db/0277_tenant_contract_and_merge_fix.sql` still names `db-pending/0277_private_columns_contract_rollback.sql`; the actual rollback is `db-pending/0277_tenant_contract_and_merge_fix_rollback.sql`. The migration text is not edited, because its SHA-256 is recorded on Neon (`2ae4306f…`).
- 0278_zk_inquiries_and_rve1_payloads.sql (EXPAND, purely additive): applied on Neon (2026-11-15 18:45 UTC, owner's GO) through `scripts/migration-rollout.ts` in one transaction (sha256 `508850f1…`), after the live pre-checks `tenant-backfill --url-env OWNER_DATABASE_URL` (52 checks, 0 deviations), `migration-history-check` and `security-definer-check` (0 deviations) and `certify-0278.ts` (CERTIFIED); moved into `db/`; CODE_SCHEMA_LEVEL is 0278. Its rollback stays here (`0278_zk_inquiries_and_rve1_payloads_rollback.sql`, refuses while sealed rows exist).
- 0279_sealed_tables_read_only_grants.sql: applied on Neon (2026-11-15, owner's GO) through `scripts/migration-rollout.ts` (sha256 `dfeb79b8…`) and moved into `db/`; CODE_SCHEMA_LEVEL is 0279. Neon's default privileges had given rout_app INSERT/UPDATE/DELETE on the three 0278 tables (RLS already refused those writes); rout_app now holds SELECT only. No rollback: re-granting writes is never wanted.

