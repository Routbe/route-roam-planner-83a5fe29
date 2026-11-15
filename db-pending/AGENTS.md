# Migrations (db/ and db-pending/)

- Every migration that creates a table revokes from rout_app every table privilege it should not have, not only from PUBLIC. Why: Neon's default privileges grant rout_app INSERT/UPDATE/DELETE on each new table (found after 0278), which a PGlite replay does not show.
- Objects Neon manages itself (tables owned by the neon_auth role) are mirrored in db/ only with conditional DDL that is a no-op on Neon (0280). Why: the replay snapshot must equal Neon without the app ever altering Neon Auth's own tables.
