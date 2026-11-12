-- Harden HTL Cloud writes: browser users read their own rows; writes are
-- performed only through an authenticated revision-checked RPC.
revoke insert, update, delete on public.htl_entries from authenticated;
drop policy if exists "HTL insert own entries" on public.htl_entries;
drop policy if exists "HTL update own entries" on public.htl_entries;

create or replace function public.htl_write_entry(
  p_id text,
  p_entry jsonb,
  p_deleted boolean,
  p_expected_revision bigint
) returns bigint
language plpgsql
security definer
set search_path = ''
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

  if p_expected_revision is null then
    insert into public.htl_entries (user_id,id,entry,deleted,revision)
    values (v_user,p_id,case when p_deleted then null else p_entry end,p_deleted,1)
    on conflict (user_id,id) do nothing
    returning revision into v_revision;
    if found then return v_revision; end if;
    raise exception 'HTL_CONFLICT' using errcode = '40001';
  end if;

  update public.htl_entries
    set entry = case when p_deleted then null else p_entry end,
        deleted = p_deleted,
        revision = revision + 1,
        updated_at = now()
  where user_id = v_user and id = p_id and revision = p_expected_revision
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
