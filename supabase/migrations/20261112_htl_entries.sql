-- HTL Cloud v1: private per-user training entries with optimistic revisions.
-- Apply once in Supabase SQL editor. No existing browser data is changed.
create table if not exists public.htl_entries (
  user_id uuid not null references auth.users(id) on delete cascade,
  id text not null check (char_length(id) between 1 and 160),
  entry jsonb,
  deleted boolean not null default false,
  revision bigint not null default 1 check (revision > 0),
  updated_at timestamptz not null default now(),
  primary key (user_id, id),
  constraint htl_entry_payload check (
    (deleted = true and entry is null)
    or
    (deleted = false and entry is not null
      and jsonb_typeof(entry) = 'object'
      and entry->>'id' = id)
  )
);
create index if not exists htl_entries_user_updated_idx
  on public.htl_entries (user_id, updated_at desc);
alter table public.htl_entries enable row level security;
revoke all on table public.htl_entries from public, anon, authenticated;
grant select, insert, update on public.htl_entries to authenticated;

create policy "HTL read own entries" on public.htl_entries
  for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "HTL insert own entries" on public.htl_entries
  for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "HTL update own entries" on public.htl_entries
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

-- Writers supply the revision last observed. Stale writes fail instead of silently
-- overwriting changes made on another device. Deletions are tombstones.
create or replace function public.htl_write_entry(
  p_id text,
  p_entry jsonb,
  p_deleted boolean,
  p_expected_revision bigint
) returns bigint
language plpgsql
security invoker
set search_path = public
as $$
declare
  v_user uuid := auth.uid();
  v_revision bigint;
begin
  if v_user is null then
    raise exception 'HTL_UNAUTHENTICATED' using errcode = '28000';
  end if;
  if p_id is null or char_length(p_id) not between 1 and 160 then
    raise exception 'HTL_INVALID_ID' using errcode = '22023';
  end if;
  if p_deleted is null or (not p_deleted and (
    p_entry is null
    or jsonb_typeof(p_entry) is distinct from 'object'
    or p_entry->>'id' is distinct from p_id
  )) then
    raise exception 'HTL_INVALID_ENTRY' using errcode = '22023';
  end if;

  -- Insert succeeds only for a brand-new item. Existing IDs take the
  -- revision-checked UPDATE path below.
  if p_expected_revision is null then
    insert into public.htl_entries (user_id, id, entry, deleted, revision)
    values (v_user, p_id, case when p_deleted then null else p_entry end, p_deleted, 1)
    on conflict (user_id, id) do nothing
    returning revision into v_revision;
    if found then return v_revision; end if;
    raise exception 'HTL_CONFLICT' using errcode = '40001';
  end if;

  update public.htl_entries
  set entry = case when p_deleted then null else p_entry end,
      deleted = p_deleted,
      revision = revision + 1,
      updated_at = now()
  where user_id = v_user
    and id = p_id
    and revision = p_expected_revision
  returning revision into v_revision;
  if not found then
    raise exception 'HTL_CONFLICT' using errcode = '40001';
  end if;
  return v_revision;
end;
$$;
revoke all on function public.htl_write_entry(text,jsonb,boolean,bigint)
  from public, anon;
grant execute on function public.htl_write_entry(text,jsonb,boolean,bigint)
  to authenticated;
