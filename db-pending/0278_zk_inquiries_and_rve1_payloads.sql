-- 0278 (EXPAND): sealed booking payloads, sealed profile-card requests and host booking keys in Neon.
--
-- Replaces the S3 stopgaps of 2026-11-15 (users/<uid>/booking-key.json and
-- users/<uid>/inquiries/<pid>.json): transactional state and RVE1 ciphertext live in
-- PostgreSQL only; object storage keeps media and pinned Wasm.
--
--   public.booking_host_keys  one published booking key per host (public key + seed sealed
--                             under the host's workspace key; the server can open neither)
--   public.inquiries          sealed profile-card requests (one RVE1 bkh envelope each)
--   public.booking_payloads   the host copy of a sealed booking, one row per booking row
--
-- Every ciphertext row carries the RVE1 envelope (base64url, one of three padded sizes),
-- its BLAKE3 hash (unique: a solved proof-of-work cannot be replayed), the Hashcash nonce
-- and the 10-minute epoch bucket the nonce was solved for. The server verifies the
-- proof-of-work before calling these functions; the functions re-check the bucket on the
-- database clock. BLAKE3 itself is not available in PostgreSQL, so the hash is computed
-- by the server from the bytes it validated.
--
-- rout_app gets SELECT only, through RLS keyed on the caller (rout.current_user_id).
-- Every write goes through the SECURITY DEFINER functions below, which take the caller
-- from the transaction context, never from a parameter.
-- Legacy rows are untouched: booking_requests and bookings.intake_answers v2 stay readable.
-- Rollback: db-pending/0278_zk_inquiries_and_rve1_payloads_rollback.sql.

create table public.booking_host_keys (
  host_user_id uuid primary key references public.users(id) on delete cascade,
  host_ref uuid not null unique,
  kid text not null check (kid ~ '^[A-Za-z0-9_-]{22}$'),
  public_key text not null check (public_key ~ '^[A-Za-z0-9_-]+$' and length(public_key) = 2134),
  sealed_seed text not null check (sealed_seed ~ '^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{64}$'),
  key_id text not null check (length(key_id) between 1 and 200),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.inquiries (
  id uuid primary key default gen_random_uuid(),
  host_user_id uuid not null references public.users(id) on delete cascade,
  payload_id uuid not null unique,
  host_ref uuid not null,
  preferred_date date not null,
  preferred_time text not null check (preferred_time ~ '^[0-9]{2}:[0-9]{2}$'),
  duration_minutes integer not null check (duration_minutes between 5 and 1440),
  title text check (title is null or length(title) <= 200),
  status text not null default 'pending' check (status in ('pending', 'accepted', 'declined')),
  encrypted_rve1_payload text not null check (
    encrypted_rve1_payload ~ '^[A-Za-z0-9_-]+$' and length(encrypted_rve1_payload) in (3583, 7679, 24063)
    and left(encrypted_rve1_payload, 8) = 'UlZFMQEF'),
  blake3_payload_hash bytea not null unique check (octet_length(blake3_payload_hash) = 32),
  pow_nonce text not null check (pow_nonce ~ '^[0-9a-f]{16}$'),
  epoch_bucket integer not null check (epoch_bucket > 0),
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);
create index inquiries_host_idx on public.inquiries (host_user_id, created_at desc);

create table public.booking_payloads (
  booking_id uuid primary key references public.bookings(id) on delete cascade,
  host_user_id uuid not null references public.users(id) on delete cascade,
  payload_id uuid not null,
  host_ref uuid not null,
  encrypted_rve1_payload text not null check (
    encrypted_rve1_payload ~ '^[A-Za-z0-9_-]+$' and length(encrypted_rve1_payload) in (3583, 7679, 24063)
    and left(encrypted_rve1_payload, 8) = 'UlZFMQEF'),
  blake3_payload_hash bytea not null unique check (octet_length(blake3_payload_hash) = 32),
  pow_nonce text not null check (pow_nonce ~ '^[0-9a-f]{16}$'),
  epoch_bucket integer not null check (epoch_bucket > 0),
  created_at timestamptz not null default now(),
  unique (payload_id, host_user_id)
);
create index booking_payloads_host_idx on public.booking_payloads (host_user_id);

-- Grants: read-only for rout_app, nothing for PUBLIC; writes only through the definers below.
revoke all on public.booking_host_keys, public.inquiries, public.booking_payloads from public;
grant select on public.booking_host_keys, public.inquiries, public.booking_payloads to rout_app;

alter table public.booking_host_keys enable row level security;
alter table public.inquiries enable row level security;
alter table public.booking_payloads enable row level security;

create policy booking_host_keys_owner_read on public.booking_host_keys for select to rout_app
  using (host_user_id = (select public.rout_current_user_id()));
create policy inquiries_host_read on public.inquiries for select to rout_app
  using (host_user_id = (select public.rout_current_user_id()));
create policy booking_payloads_host_read on public.booking_payloads for select to rout_app
  using (host_user_id = (select public.rout_current_user_id()));

-- Shape of one RVE1 bkh envelope in base64url (header RVE1 / suite 1 / kind bkh; three padded sizes).
create or replace function public.rout_sealed_envelope_ok(p text)
returns boolean language sql immutable security definer set search_path = pg_catalog, pg_temp as $$
  select p is not null and p ~ '^[A-Za-z0-9_-]+$' and pg_catalog.length(p) in (3583, 7679, 24063)
     and pg_catalog.left(p, 8) = 'UlZFMQEF'
$$;

-- The proof-of-work epoch must be within one 10-minute bucket of the database clock.
create or replace function public.rout_sealed_epoch_ok(p integer)
returns boolean language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select p is not null
     and pg_catalog.abs(p - pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.now()) / 600)::integer) <= 1
$$;

-- The caller publishes (or confirms) its own booking key. A different key never replaces
-- a published one unless p_replace is the host's explicit choice.
create or replace function public.rout_booking_host_key_publish(p_host_ref uuid, p_kid text, p_public_key text,
  p_sealed_seed text, p_key_id text, p_replace boolean)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v_uid uuid := public.rout_current_user_id(); v_kid text;
begin
  if v_uid is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'input'); end if;
  if p_host_ref is null or p_kid is null or p_kid !~ '^[A-Za-z0-9_-]{22}$'
     or p_public_key is null or p_public_key !~ '^[A-Za-z0-9_-]+$' or pg_catalog.length(p_public_key) <> 2134
     or p_sealed_seed is null or p_sealed_seed !~ '^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{64}$'
     or p_key_id is null or pg_catalog.length(p_key_id) not between 1 and 200 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'input');
  end if;
  select k.kid into v_kid from public.booking_host_keys k where k.host_user_id = v_uid for update;
  if v_kid = p_kid then return pg_catalog.jsonb_build_object('ok', true, 'kid', p_kid); end if;
  if v_kid is not null and not coalesce(p_replace, false) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'exists');
  end if;
  begin
    insert into public.booking_host_keys (host_user_id, host_ref, kid, public_key, sealed_seed, key_id)
    values (v_uid, p_host_ref, p_kid, p_public_key, p_sealed_seed, p_key_id)
    on conflict (host_user_id) do update
      set host_ref = excluded.host_ref, kid = excluded.kid, public_key = excluded.public_key,
          sealed_seed = excluded.sealed_seed, key_id = excluded.key_id, updated_at = pg_catalog.now();
  exception when unique_violation then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'input');
  end;
  return pg_catalog.jsonb_build_object('ok', true, 'kid', p_kid);
end $$;

-- Public keys of every host of a public event type (references only, never user ids).
create or replace function public.rout_booking_event_host_keys(p_event_type uuid)
returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select case when public.rout_booking_type_public(p_event_type) then pg_catalog.jsonb_build_object(
    'hosts', (select pg_catalog.count(*) from public.booking_event_type_hosts h where h.event_type_id = p_event_type),
    'keys', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('ref', k.host_ref, 'kid', k.kid, 'publicKey', k.public_key) order by k.host_ref)
       from public.booking_event_type_hosts h join public.booking_host_keys k on k.host_user_id = h.user_id
      where h.event_type_id = p_event_type), '[]'::jsonb))
  else pg_catalog.jsonb_build_object('hosts', 0, 'keys', '[]'::jsonb) end
$$;

-- Public key behind a profile's visible request form, or null.
create or replace function public.rout_booking_profile_host_key(p_profile uuid)
returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select pg_catalog.jsonb_build_object('ref', k.host_ref, 'kid', k.kid, 'publicKey', k.public_key)
    from public.booking_host_keys k
   where k.host_user_id = p_profile
     and exists (
       select 1 from public.profiles p
        cross join lateral pg_catalog.jsonb_array_elements(case when pg_catalog.jsonb_typeof(p.blocks) = 'array' then p.blocks else '[]'::jsonb end) b(el)
        where p.id = p_profile and b.el->>'kind' = 'booking_request'
          and coalesce(b.el->'hidden', 'false'::jsonb) <> 'true'::jsonb)
$$;

-- One sealed profile-card request. Anonymous visitors call it through the server, which has
-- already checked the envelope header against the host's key and the proof-of-work.
create or replace function public.rout_inquiry_create_sealed(p_profile uuid, p_payload_id uuid, p_host_ref uuid,
  p_date date, p_time text, p_duration integer, p_title text, p_envelope text, p_hash bytea,
  p_pow_nonce text, p_epoch integer)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v_id uuid;
begin
  if p_profile is null or p_payload_id is null or p_host_ref is null or p_date is null
     or p_time is null or p_time !~ '^[0-9]{2}:[0-9]{2}$'
     or p_duration is null or p_duration not between 5 and 1440 or coalesce(pg_catalog.length(p_title), 0) > 200
     or not public.rout_sealed_envelope_ok(p_envelope)
     or p_hash is null or pg_catalog.octet_length(p_hash) <> 32
     or p_pow_nonce is null or p_pow_nonce !~ '^[0-9a-f]{16}$' then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  if not public.rout_sealed_epoch_ok(p_epoch) then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'pow_stale'); end if;
  if p_date < (pg_catalog.now() - interval '1 day')::date then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'past_date'); end if;
  if public.rout_booking_profile_host_key(p_profile) is null then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'unavailable');
  end if;
  if not exists (select 1 from public.booking_host_keys k where k.host_user_id = p_profile and k.host_ref = p_host_ref) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  -- Flood ceiling per host on top of the proof-of-work.
  if (select pg_catalog.count(*) from public.inquiries i
       where i.host_user_id = p_profile and i.created_at > pg_catalog.now() - interval '1 hour') >= 60 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'rate_limited');
  end if;
  begin
    insert into public.inquiries (host_user_id, payload_id, host_ref, preferred_date, preferred_time, duration_minutes,
      title, encrypted_rve1_payload, blake3_payload_hash, pow_nonce, epoch_bucket)
    values (p_profile, p_payload_id, p_host_ref, p_date, p_time, p_duration, nullif(p_title, ''), p_envelope, p_hash,
      p_pow_nonce, p_epoch)
    returning id into v_id;
  exception when unique_violation then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'duplicate');
  end;
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $$;

-- The host decides on one of its own pending requests (caller from the transaction context).
create or replace function public.rout_inquiry_resolve(p_id uuid, p_action text)
returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare v_uid uuid := public.rout_current_user_id();
begin
  if v_uid is null or p_id is null or p_action is null or p_action not in ('accept', 'decline') then return false; end if;
  update public.inquiries i
     set status = case when p_action = 'accept' then 'accepted' else 'declined' end, resolved_at = pg_catalog.now()
   where i.id = p_id and i.host_user_id = v_uid and i.status = 'pending';
  return found;
end $$;

-- A sealed booking in one transaction: the booking rows (placeholders only, db/0218) and, for
-- each booked host, that host's envelope. p_copies = [{ref, envelope, hash(hex)}], exactly one
-- per host of the type, each bound to that host's published key reference. Any failure after
-- the booking rows exist rolls the whole statement back.
create or replace function public.rout_booking_create_sealed(p_event_type uuid, p_start timestamptz,
  p_guest_timezone text, p_payload_id uuid, p_copies jsonb, p_pow_nonce text, p_epoch integer,
  p_hold uuid, p_hold_secret text)
returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_hosts integer; v_bound integer; v_n integer; r jsonb; i integer; v_bid uuid; v_host uuid; v_ref uuid; c jsonb;
begin
  if p_event_type is null or p_payload_id is null or p_copies is null or pg_catalog.jsonb_typeof(p_copies) <> 'array'
     or p_pow_nonce is null or p_pow_nonce !~ '^[0-9a-f]{16}$' then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid_intake');
  end if;
  v_n := pg_catalog.jsonb_array_length(p_copies);
  if v_n not between 1 and 8 then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid_intake'); end if;
  for c in select e from pg_catalog.jsonb_array_elements(p_copies) e loop
    if pg_catalog.jsonb_typeof(c) <> 'object' or coalesce(c->>'ref', '') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       or not public.rout_sealed_envelope_ok(c->>'envelope') or coalesce(c->>'hash', '') !~ '^[0-9a-f]{64}$' then
      return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid_intake');
    end if;
  end loop;
  if not public.rout_sealed_epoch_ok(p_epoch) then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'pow_stale'); end if;
  if not public.rout_booking_type_public(p_event_type) then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'inactive'); end if;

  select pg_catalog.count(*) into v_hosts from public.booking_event_type_hosts h where h.event_type_id = p_event_type;
  select pg_catalog.count(distinct h.user_id) into v_bound
    from public.booking_event_type_hosts h join public.booking_host_keys k on k.host_user_id = h.user_id
   where h.event_type_id = p_event_type
     and exists (select 1 from pg_catalog.jsonb_array_elements(p_copies) e where (e->>'ref')::uuid = k.host_ref);
  if v_hosts = 0 or v_bound <> v_hosts or v_n <> v_hosts then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'host_key_missing');
  end if;

  r := public.rout_booking_create(p_event_type, p_start, 'RVE1', p_payload_id::text || '@sealed.invalid',
    p_guest_timezone, null, pg_catalog.jsonb_build_object('v', 3, 'pid', p_payload_id), p_hold, p_hold_secret);
  if not coalesce((r->>'ok')::boolean, false) then return r; end if;

  for i in 0 .. pg_catalog.jsonb_array_length(r->'bookingIds') - 1 loop
    v_bid := (r->'bookingIds'->>i)::uuid;
    v_host := (r->'hostIds'->>i)::uuid;
    select k.host_ref into v_ref from public.booking_host_keys k where k.host_user_id = v_host;
    select e into c from pg_catalog.jsonb_array_elements(p_copies) e where (e->>'ref')::uuid = v_ref;
    if c is null then raise exception 'sealed copy missing' using errcode = 'P0001'; end if;
    insert into public.booking_payloads (booking_id, host_user_id, payload_id, host_ref, encrypted_rve1_payload,
      blake3_payload_hash, pow_nonce, epoch_bucket)
    values (v_bid, v_host, p_payload_id, v_ref, c->>'envelope', pg_catalog.decode(c->>'hash', 'hex'), p_pow_nonce, p_epoch);
  end loop;
  return r;
end $$;

-- Function rights, stated explicitly (Neon's default privileges are not relied on).
revoke all on function public.rout_sealed_envelope_ok(text) from public, rout_app;
revoke all on function public.rout_sealed_epoch_ok(integer) from public, rout_app;
revoke all on function public.rout_booking_host_key_publish(uuid, text, text, text, text, boolean) from public;
revoke all on function public.rout_booking_event_host_keys(uuid) from public;
revoke all on function public.rout_booking_profile_host_key(uuid) from public;
revoke all on function public.rout_inquiry_create_sealed(uuid, uuid, uuid, date, text, integer, text, text, bytea, text, integer) from public;
revoke all on function public.rout_inquiry_resolve(uuid, text) from public;
revoke all on function public.rout_booking_create_sealed(uuid, timestamptz, text, uuid, jsonb, text, integer, uuid, text) from public;
grant execute on function public.rout_booking_host_key_publish(uuid, text, text, text, text, boolean) to rout_app;
grant execute on function public.rout_booking_event_host_keys(uuid) to rout_app;
grant execute on function public.rout_booking_profile_host_key(uuid) to rout_app;
grant execute on function public.rout_inquiry_create_sealed(uuid, uuid, uuid, date, text, integer, text, text, bytea, text, integer) to rout_app;
grant execute on function public.rout_inquiry_resolve(uuid, text) to rout_app;
grant execute on function public.rout_booking_create_sealed(uuid, timestamptz, text, uuid, jsonb, text, integer, uuid, text) to rout_app;
