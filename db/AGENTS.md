# Migrations in db/

- Every migration that creates a table revokes from rout_app every table privilege it should not have, not only from PUBLIC. Why: Neon's default privileges grant rout_app INSERT/UPDATE/DELETE on each new table (found after 0278), which a PGlite replay does not show.
