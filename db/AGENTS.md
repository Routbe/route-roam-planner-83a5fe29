# Migrations in db/

- Objects Neon manages itself (tables owned by the neon_auth role) are mirrored here only with conditional DDL that is a no-op on Neon (0280). Why: the replay snapshot must equal Neon without the app ever altering Neon Auth's own tables.
