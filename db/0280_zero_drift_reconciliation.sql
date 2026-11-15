-- 0280: zero-drift reconciliation between Neon and an offline replay of db/.
--
-- schema-snapshot --check listed four differences after 0279; none changes behaviour:
-- 1. public.rout_pow_spend and 2. public.sync_social_grid_draft: the live bodies are the
--    same token stream as db/ (0206/0184) with their line breaks collapsed when they were
--    first applied through the gateway. Each is re-created below with the exact body text
--    an offline replay of db/ produces, so pg_proc.prosrc on Neon equals the replay byte
--    for byte. Owner, volatility and grants stay the same: CREATE OR REPLACE keeps the ACL,
--    and the rout_app grants are restated explicitly below. The trigger function's
--    search_path moves from pg_catalog, public to pg_catalog, pg_temp (the rule for every
--    migration from 0255 on): its body names every table with public. and uses only
--    pg_catalog functions and types, so nothing resolves differently.
-- 3. neon_auth.project_config.auth_logs_export_enabled was added on Neon by Neon Auth
--    itself (the table is owned by the neon_auth role, not by this database's owner). The
--    replay adds the same column only when it is missing, so on Neon this is a no-op and
--    the Neon-managed table is never altered.
-- 4. "schema grants differ" was a key-order artefact of the comparison script (same
--    four rout_app USAGE grants on both sides); it is fixed in scripts/schema-catalog.ts,
--    not here.
-- No data is touched.

CREATE OR REPLACE FUNCTION public.rout_pow_spend(p_hash text, p_scope text, p_expires_at timestamp with time zone)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
declare inserted int;
begin
  delete from public.pow_spent_challenges where expires_at < now() - interval '1 minute';
  insert into public.pow_spent_challenges (challenge_hash, scope, expires_at)
  values (p_hash, p_scope, least(p_expires_at, now() + interval '15 minutes'))
  on conflict (challenge_hash) do nothing;
  get diagnostics inserted = row_count;
  return inserted = 1;
end $function$;
revoke all on function public.rout_pow_spend(text, text, timestamp with time zone) from public;
grant execute on function public.rout_pow_spend(text, text, timestamp with time zone) to rout_app;

CREATE OR REPLACE FUNCTION public.sync_social_grid_draft()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'pg_temp'
AS $function$
declare
  b jsonb;
  config jsonb;
  item jsonb;
  ordinal bigint;
  kept uuid[] := '{}';
  card_id uuid;
begin
  for b in select value from jsonb_array_elements(coalesce(new.payload->'blocks','[]'::jsonb)) loop
    if b->>'kind' <> 'social_grid' then continue; end if;
    begin
      config := (b->>'value')::jsonb;
    exception when invalid_text_representation then
      continue;
    end;
    if jsonb_typeof(config->'items') <> 'array' then continue; end if;
    for item, ordinal in select value, ordinality from jsonb_array_elements(config->'items') with ordinality loop
      if ordinal > 30 or coalesce(item->>'id','') = '' or coalesce(item->>'mediaUrl','') = '' then continue; end if;
      insert into public.social_grid_items
        (user_id, profile_space, block_id, source_item_id, platform, media_url, caption, target_url, is_pinned, is_video, position, created_at)
      values (new.user_id, new.space, b->>'id', item->>'id',
        case when item->>'platform' in ('instagram','tiktok','article','custom') then item->>'platform' else 'custom' end,
        item->>'mediaUrl', coalesce(item->>'caption',''), nullif(item->>'targetUrl',''),
        coalesce(item->'pinned' = 'true'::jsonb,false), coalesce(item->'isVideo' = 'true'::jsonb,false),
        ordinal - 1, coalesce(nullif(item->>'createdAt','')::timestamptz, now()))
      on conflict (user_id, profile_space, block_id, source_item_id) do update set
        platform=excluded.platform, media_url=excluded.media_url, caption=excluded.caption,
        target_url=excluded.target_url, is_pinned=excluded.is_pinned, is_video=excluded.is_video,
        position=excluded.position
      returning id into card_id;
      kept := array_append(kept, card_id);
    end loop;
  end loop;
  delete from public.social_grid_items
    where user_id=new.user_id and profile_space=new.space and not (id = any(kept));
  return new;
end $function$;
grant execute on function public.sync_social_grid_draft() to rout_app;

do $neon_auth$
begin
  if not exists (
    select 1 from information_schema.columns
     where table_schema = 'neon_auth' and table_name = 'project_config' and column_name = 'auth_logs_export_enabled'
  ) then
    alter table neon_auth.project_config add column auth_logs_export_enabled boolean default false;
  end if;
end $neon_auth$;
