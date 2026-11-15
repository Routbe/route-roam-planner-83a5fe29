-- Rollback of 0278_zk_inquiries_and_rve1_payloads.sql. Idempotent. Refuses once any sealed
-- request, sealed booking payload or published booking key exists: dropping them would destroy
-- ciphertext only the hosts can open.
do $rollback$
begin
  if (to_regclass('public.inquiries') is not null and exists (select 1 from public.inquiries))
     or (to_regclass('public.booking_payloads') is not null and exists (select 1 from public.booking_payloads))
     or (to_regclass('public.booking_host_keys') is not null and exists (select 1 from public.booking_host_keys)) then
    raise exception '0278 rollback refused: sealed rows exist' using errcode = 'P0001';
  end if;
end $rollback$;

drop function if exists public.rout_booking_create_sealed(uuid, timestamptz, text, uuid, jsonb, text, integer, uuid, text);
drop function if exists public.rout_inquiry_resolve(uuid, text);
drop function if exists public.rout_inquiry_create_sealed(uuid, uuid, uuid, date, text, integer, text, text, bytea, text, integer);
drop function if exists public.rout_booking_profile_host_key(uuid);
drop function if exists public.rout_booking_event_host_keys(uuid);
drop function if exists public.rout_booking_host_key_publish(uuid, text, text, text, text, boolean);
drop function if exists public.rout_sealed_epoch_ok(integer);
drop function if exists public.rout_sealed_envelope_ok(text);
drop table if exists public.booking_payloads;
drop table if exists public.inquiries;
drop table if exists public.booking_host_keys;
