# db/ — replayed migrations

Every `NNNN_*.sql` file here is replayed in order by the runners (`scripts/migrate.ts`, `scripts/migrate-gateway.ts`), the offline replay (`scripts/formal-rls/replay.ts`) and the snapshot check. Held-back files live in `db-pending/`, retired ones in `db-archive/`.

## Current state (2026-11-15 19:12 UTC)

- Schema level **0280** (`CODE_SCHEMA_LEVEL` in `src/lib/schema-version.ts`), 274 rows in `public.schema_migrations` on Neon.
- `bun scripts/schema-snapshot.ts --check` against Neon: **0 differences** with `db/schema.snapshot.json` (which is produced by an offline replay of this folder).
- `bun scripts/tenant-backfill.ts --url-env OWNER_DATABASE_URL`: 51 checks, 0 deviations.
- `bun scripts/migration-history-check.ts` and `bun scripts/security-definer-check.ts`: 0 deviations (432 SECURITY DEFINER functions, all on `pg_catalog, pg_temp`).
- `bun scripts/formal-rls/certify-0280.ts --url-env OWNER_DATABASE_URL`: CERTIFIED on the live catalog (1225 obligations, 547 Z3 checks, 0 unproven); report in `docs/rls-0280-certification.md`.

## Rules

- `schema.snapshot.json` is written by `bun scripts/schema-replay-snapshot.ts` (replay), never edited by hand; Neon must match it.
- One-file rollouts go through `scripts/migration-rollout.ts` (checksum-bound, one transaction, definer guard).
- Objects Neon manages itself (tables owned by the `neon_auth` role) are mirrored here only with conditional DDL that is a no-op on Neon (see 0280).
