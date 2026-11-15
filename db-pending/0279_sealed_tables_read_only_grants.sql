-- 0279: rout_app keeps only SELECT on the three sealed-payload tables from 0278.
--
-- 0278 granted SELECT to rout_app and revoked everything from PUBLIC, but Neon's
-- default privileges (neondb_owner: tables -> rout_app=arwd) also gave rout_app
-- INSERT, UPDATE and DELETE on every new table. RLS already refuses those writes
-- (only FOR SELECT policies exist), so nothing was writable; this file makes the
-- grants match the stated contract and an offline replay of db/, so a later
-- permissive policy can never open a direct write path. Writes stay exclusively
-- in the SECURITY DEFINER functions of 0278. No data is touched.
revoke insert, update, delete, truncate, references, trigger
  on public.booking_host_keys, public.inquiries, public.booking_payloads from rout_app;
grant select on public.booking_host_keys, public.inquiries, public.booking_payloads to rout_app;
