-- ============================================================================
-- DerOps Supabase Security Check  v1.2
-- https://derops.dev/check
--
-- READ-ONLY: this is a single SELECT statement. It reads the Postgres catalog
-- (table/policy/function definitions). It never reads your rows, never writes,
-- and never sends anything anywhere.
--
-- How to use:
--   1. Supabase Dashboard -> SQL Editor -> New query
--   2. Paste this whole file and click Run
--   3. Copy the single "report" cell and paste it at derops.dev/check
-- ============================================================================
with
r as (
  select (select oid from pg_roles where rolname = 'anon')          as anon,
         (select oid from pg_roles where rolname = 'authenticated') as authd
),
sys as (
  select unnest(array[
    'pg_catalog','information_schema','auth','storage','extensions','graphql','graphql_public',
    'realtime','_realtime','supabase_functions','supabase_migrations','vault','pgsodium',
    'pgsodium_masks','net','cron','pgbouncer','_analytics','pgtle','topology','tiger','tiger_data'
  ]) as nsp
),
-- schemas the API roles can reach (public, plus any custom schema you exposed)
api_ns as (
  select n.oid, n.nspname
  from pg_namespace n, r
  where n.nspname not in (select nsp from sys)
    and n.nspname not like 'pg\_%'
    and (coalesce(has_schema_privilege(r.anon,  n.oid, 'USAGE'), false)
      or coalesce(has_schema_privilege(r.authd, n.oid, 'USAGE'), false))
),
rels as (
  select c.oid, ns.nspname, c.relname, c.relkind, c.relrowsecurity, c.reloptions,
         format('%I.%I', ns.nspname, c.relname) as fq,
         coalesce(has_table_privilege(r.anon,  c.oid, 'SELECT'), false) as anon_sel,
         coalesce(has_table_privilege(r.anon,  c.oid, 'INSERT, UPDATE, DELETE'), false) as anon_write,
         coalesce(has_table_privilege(r.authd, c.oid, 'SELECT'), false) as auth_sel,
         coalesce(has_table_privilege(r.authd, c.oid, 'INSERT, UPDATE, DELETE'), false) as auth_write,
         (select string_agg(a.attname, ', ' order by a.attnum)
            from pg_attribute a
           where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
             and a.attname ~* '(email|phone|mobile|password|passwd|secret|token|api_?key|ssn|national_id|passport|iban|card|address|birth|dob|salary)'
         ) as sensitive_cols,
         exists (select 1 from pg_attribute a
                  where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
                    and a.attname ~* '^(user|owner|author|created_by|tenant|org|organization|account|customer|client|clinic|company|team|workspace|patient|member|profile|venue|store|shop)(_?id|_?uuid)?$'
         ) as has_owner_col
  from pg_class c
  join api_ns ns on ns.oid = c.relnamespace, r
  where c.relkind in ('r','p','v','m','f')
    and not exists (select 1 from pg_depend d
                     where d.classid = 'pg_class'::regclass and d.objid = c.oid and d.deptype = 'e')
),
pols as (
  select p.polname,
         c.oid as relid,
         format('%I.%I', n.nspname, c.relname) as fq,
         p.polpermissive,
         case p.polcmd when 'r' then 'SELECT' when 'a' then 'INSERT' when 'w' then 'UPDATE'
                       when 'd' then 'DELETE' else 'ALL' end as cmd,
         coalesce(pg_get_expr(p.polqual, p.polrelid), '')      as qual,
         coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') as chk,
         coalesce(0 = any(p.polroles) or r.anon  = any(p.polroles), false) as to_anon,
         coalesce(0 = any(p.polroles) or r.authd = any(p.polroles), false) as to_auth,
         coalesce(has_table_privilege(r.anon,  c.oid, 'SELECT'), false) as anon_sel,
         coalesce(has_table_privilege(r.anon,  c.oid, 'INSERT, UPDATE, DELETE'), false) as anon_write,
         coalesce(has_table_privilege(r.authd, c.oid, 'SELECT'), false) as auth_sel,
         coalesce(has_table_privilege(r.authd, c.oid, 'INSERT, UPDATE, DELETE'), false) as auth_write,
         exists (select 1 from pg_policy x where x.polrelid = p.polrelid and not x.polpermissive) as has_restrictive,
         n.nspname = 'storage' as is_storage
  from pg_policy p
  join pg_class c     on c.oid = p.polrelid
  join pg_namespace n on n.oid = c.relnamespace, r
  where n.nspname in (select nspname from api_ns) or n.nspname = 'storage'
),
pols2 as (
  select *,
         (cmd in ('SELECT','ALL') and qual = 'true') as read_open,
         ((cmd = 'INSERT' and chk = 'true') or (cmd in ('UPDATE','DELETE','ALL') and qual = 'true')) as write_open,
         (cmd = 'INSERT') as insert_only
  from pols
  where polpermissive
),
-- functions in API schemas, with a rough read of their bodies
fns as (
  select p.oid, p.proname, p.prosecdef, p.prorettype,
         p.oid::regprocedure::text as sig,
         coalesce(nullif(p.prosrc, ''), pg_get_functiondef(p.oid)) as src,
         coalesce(array_to_string(p.proargnames, ','), '') as argnames,
         coalesce(has_function_privilege(r.anon,  p.oid, 'EXECUTE'), false) as anon_exec,
         coalesce(has_function_privilege(r.authd, p.oid, 'EXECUTE'), false) as auth_exec
  from pg_proc p join api_ns ns on ns.oid = p.pronamespace, r
  where p.prokind = 'f'
    and not exists (select 1 from pg_depend d where d.classid = 'pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e')
),
fns2 as (
  select *, src ~* '(auth\.(uid|jwt|role)\s*\(|current_setting\(\s*''request\.jwt)' as direct_auth
  from fns
),
-- every function that checks the caller, directly or through any chain of helper calls
checkers (oid, proname) as (
  with recursive c(oid, proname) as (
    select oid, proname from fns2 where direct_auth
    union
    select f.oid, f.proname from fns2 f join c on f.oid <> c.oid
     where f.src ~* ('\m' || c.proname || '\s*\(')
  )
  select oid, proname from c
),
dfns as (  -- SECURITY DEFINER functions the API roles can call
  select f.*,
         exists (select 1 from checkers k where k.oid = f.oid) as has_check,
         f.argnames ~* '(token|secret|code|key|hash)' as token_param,
         f.src ~* '\m(insert\s+into|update\s+\S+\s+set|delete\s+from|truncate)\M' as writes
  from fns2 f
  where f.prosecdef
    and f.prorettype not in ('trigger'::regtype, 'event_trigger'::regtype)
    and (f.anon_exec or f.auth_exec)
),
dfns2 as (select *, (has_check or token_param) as gated from dfns),
findings as (

  -- 1. RLS disabled on a table the API can reach
  select 'rls_disabled' as check_id,
         case when anon_sel or anon_write then 'critical' else 'high' end as severity,
         fq as object,
         concat(
           'Row Level Security is OFF. ',
           case when anon_sel or anon_write
                then 'Anyone holding your public anon key (it ships in your frontend) can '
                else 'Any signed-in user can ' end,
           concat_ws(' and ',
             case when anon_sel or auth_sel then 'read every row' end,
             case when anon_write or auth_write then 'insert/update/delete rows' end),
           ' through the REST API.',
           case when sensitive_cols is not null then ' Sensitive-looking columns: ' || sensitive_cols || '.' end
         ) as detail,
         format('alter table %s enable row level security;  -- then add policies scoped to (select auth.uid())', fq) as fix
  from rels
  where relkind in ('r','p') and not relrowsecurity
    and (anon_sel or anon_write or auth_sel or auth_write)

  union all
  -- 2. RLS on, but no policies at all (locked; often intentional)
  select 'rls_no_policy', 'info', fq,
         'RLS is on with no policies, so the API can''t read or write this table (only service_role can). Fine if intended; if your app uses it, it is silently getting empty results.',
         format('-- if the app needs it: create policy "..." on %s for select to authenticated using (user_id = (select auth.uid()));', fq)
  from rels
  where relkind in ('r','p') and relrowsecurity
    and not exists (select 1 from pg_policy p where p.polrelid = rels.oid)

  union all
  -- 3a. Policy that lets everyone read every row
  select 'policy_open_read',
         case when to_anon and anon_sel and exists (select 1 from rels x where x.oid = relid and x.sensitive_cols is not null) then 'critical'
              when to_anon and anon_sel then 'high'
              when ref_data then 'low'
              else 'medium' end,
         fq || '  (policy "' || polname || '")',
         concat(
           case when to_anon and anon_sel
                then 'USING (true) for anon: anyone with your anon key can read every row.'
                when ref_data
                then 'USING (true) for authenticated on a table with no owner column: this looks like shared reference data that every signed-in user may read. Fine if so.'
                else 'USING (true) for authenticated: any signed-up user can read every row, and signup is usually open to anyone.' end,
           (select ' Sensitive-looking columns: ' || x.sensitive_cols || '.' from rels x where x.oid = relid and x.sensitive_cols is not null),
           case when has_restrictive then ' (A RESTRICTIVE policy exists on this table and may narrow this; verify.)' end
         ),
         format('drop policy %I on %s;  -- replace with e.g. using (user_id = (select auth.uid()))', polname, fq)
  from (select p.*, (not p.is_storage and exists (select 1 from rels x where x.oid = p.relid
                                                    and not x.has_owner_col and x.sensitive_cols is null)) as ref_data
          from pols2 p) pr
  where read_open and ((to_anon and anon_sel) or (to_auth and auth_sel))

  union all
  -- 3b. Policy that lets everyone write
  select 'policy_open_write',
         case when to_anon and anon_write and (not insert_only or is_storage) then 'high'
              when to_anon and anon_write then 'medium'
              when not insert_only then 'high'
              else 'low' end,
         fq || '  (policy "' || polname || '")',
         concat(
           case when to_anon and anon_write then 'Anyone with your anon key' else 'Any signed-in user' end,
           case when is_storage and insert_only then ' can upload files to your project. That invites abuse: malware hosting, phishing files and a growing storage bill.'
                when is_storage then ' can replace or delete ANY stored file, including other users'' files.'
                when insert_only then ' can insert rows. Fine for a public form if intended, but add validation and rate limiting.'
                else ' can modify or delete ANY row, including rows belonging to other users.' end
         ),
         case when is_storage
              then format('drop policy %I on %s;  -- restrict to: to authenticated with check (bucket_id = ''...'' and owner = (select auth.uid()))', polname, fq)
              else format('drop policy %I on %s;  -- scope with: with check (user_id = (select auth.uid()))', polname, fq) end
  from pols2
  where write_open and ((to_anon and anon_write) or (to_auth and auth_write))

  union all
  -- 4. Policy trusts user_metadata (the user can edit it themselves)
  select 'policy_user_metadata', 'high', fq || '  (policy "' || polname || '")',
         'Policy reads user_metadata from the JWT. Users can set their own user_metadata with supabase.auth.updateUser(), so they can grant themselves this access (e.g. role = admin).',
         'Use app_metadata (only writable server-side) or a roles table checked with (select auth.uid()).'
  from pols
  where (qual || ' ' || chk) ~* 'user_metadata'

  union all
  -- 5. auth.uid()/auth.jwt() not wrapped in a sub-select (performance)
  select 'policy_uid_not_wrapped', 'low', fq || '  (policy "' || polname || '")',
         'auth.uid()/auth.jwt() is called once per row instead of once per query. Big slowdown on large tables.',
         'Wrap it: (select auth.uid()) instead of auth.uid().'
  from pols
  where regexp_replace(qual || ' ' || chk, '\(\s*select\s+auth\.(uid|jwt|role)\(\)', '', 'gi') ~* 'auth\.(uid|jwt|role)\(\)'

  union all
  -- 6. View / materialized view exposing auth.users
  select 'auth_users_exposed', 'critical', fq,
         concat('This ', case relkind when 'm' then 'materialized view' else 'view' end,
                ' reads from auth.users and is reachable through the API, exposing user accounts',
                case when sensitive_cols is not null then ' (columns: ' || sensitive_cols || ')' end, '.'),
         format('revoke all on %s from anon, authenticated;  -- or move it to a schema the API does not expose', fq)
  from rels
  where relkind in ('v','m') and (anon_sel or auth_sel)
    and to_regclass('auth.users') is not null
    and exists (select 1 from pg_rewrite rw join pg_depend d
                  on d.classid = 'pg_rewrite'::regclass and d.objid = rw.oid
                 where rw.ev_class = rels.oid and d.refobjid = to_regclass('auth.users'))

  union all
  -- 7. View that bypasses RLS (runs as its owner)
  select 'view_bypasses_rls', case when anon_sel then 'high' else 'medium' end, fq,
         'View runs with its owner''s privileges (no security_invoker), so RLS on the tables underneath is ignored for whoever queries it.',
         format('alter view %s set (security_invoker = true);', fq)
  from rels
  where relkind = 'v' and (anon_sel or auth_sel)
    and not coalesce(array_to_string(reloptions, ',') ~* 'security_invoker=(true|on|yes|1)', false)
    and not exists (select 1 from pg_rewrite rw join pg_depend d
                      on d.classid = 'pg_rewrite'::regclass and d.objid = rw.oid
                     where rw.ev_class = rels.oid and d.refobjid = to_regclass('auth.users'))

  union all
  -- 8. Materialized view reachable by the API (RLS cannot apply)
  select 'matview_exposed', case when anon_sel and sensitive_cols is not null then 'high' else 'medium' end, fq,
         'Materialized views cannot have RLS. Everything in it is readable by '
           || case when anon_sel then 'anyone with your anon key.' else 'every signed-in user.' end,
         format('revoke select on %s from anon, authenticated;  -- serve it through a function or a private schema', fq)
  from rels
  where relkind = 'm' and (anon_sel or auth_sel)
    and not exists (select 1 from pg_rewrite rw join pg_depend d
                      on d.classid = 'pg_rewrite'::regclass and d.objid = rw.oid
                     where rw.ev_class = rels.oid and d.refobjid = to_regclass('auth.users'))

  union all
  -- 9. SECURITY DEFINER function callable through the API (/rpc).
  --    Graded by who can call it and whether its body checks the caller.
  --    Signed-in-only functions that do check the caller are not graded (counted in stats).
  select 'security_definer_function',
         case when anon_exec and not gated and writes then 'high'
              when anon_exec and not gated then 'medium'
              when anon_exec then 'low'
              else 'medium' end,
         sig,
         case when anon_exec and not gated and writes then
                'Anyone with your anon key can call this via /rest/v1/rpc. It runs as its owner (skipping RLS), changes data, and has no visible check on who is calling. If it backs a public form (bookings, sign-ups), make sure it validates every input, only writes what a visitor should, and is rate-limited.'
              when anon_exec and not gated then
                'Anyone with your anon key can call this via /rest/v1/rpc. It runs as its owner (skipping RLS) and has no visible check on who is calling. Fine only if everything it returns is meant to be public.'
              when anon_exec then
                'Anonymous visitors can call this via /rest/v1/rpc. It does '
                  || case when has_check then 'check the caller' else 'require a token' end
                  || ', so this is defense in depth: if it isn''t meant to be public, revoking anon access removes the attack surface entirely.'
              else
                'Any signed-in user can call this via /rest/v1/rpc. It runs as its owner (skipping RLS) and has no visible check on who is calling, so every user gets the same access.'
         end,
         case when anon_exec and gated
              then format('revoke execute on function %s from public, anon;  -- signed-in users keep access', sig)
              else format('revoke execute on function %s from public, anon, authenticated;  -- or add a check on (select auth.uid()) inside', sig) end
  from dfns2
  where anon_exec or not has_check

  union all
  -- 10. SECURITY DEFINER function with no fixed search_path
  select 'function_search_path_mutable', 'medium', p.oid::regprocedure::text,
         'SECURITY DEFINER function without a fixed search_path can be tricked into running objects a caller controls.',
         format('alter function %s set search_path = '''';  -- and schema-qualify names inside it', p.oid::regprocedure)
  from pg_proc p join api_ns ns on ns.oid = p.pronamespace
  where p.prosecdef
    and not exists (select 1 from pg_depend d where d.classid = 'pg_proc'::regclass and d.objid = p.oid and d.deptype = 'e')
    and not coalesce(array_to_string(p.proconfig, ',') ~* 'search_path=', false)

  union all
  -- 11. Public storage buckets
  select 'public_bucket',
         case when b.id ~* '(invoice|receipt|document|doc|private|passport|kyc|id_?card|contract|export|backup|report|statement|medical|payslip)' then 'high' else 'medium' end,
         'storage bucket "' || b.id || '"',
         'Public bucket: every file is downloadable by anyone with its URL, no login needed. Fine for avatars or marketing images, not for user documents.',
         format('update storage.buckets set public = false where id = %L;  -- then serve files with signed URLs', b.id)
  from storage.buckets b
  where b.public

  union all
  -- 12. Extensions installed in an API schema
  select 'extension_in_api_schema', 'low', e.extname || ' (in ' || ns.nspname || ')',
         'Extension objects live in an API-exposed schema, which widens what the API surface can reach.',
         format('alter extension %I set schema extensions;', e.extname)
  from pg_extension e join api_ns ns on ns.oid = e.extnamespace
  where e.extname not in ('plpgsql')
)
select jsonb_build_object(
  'tool', 'derops-supabase-check',
  'version', '1.2',
  'generated_at', now(),
  'postgres', current_setting('server_version'),
  'api_schemas', (select coalesce(jsonb_agg(nspname order by nspname), '[]') from api_ns),
  'stats', jsonb_build_object(
     'tables',        (select count(*) from rels where relkind in ('r','p')),
     'tables_rls_on', (select count(*) from rels where relkind in ('r','p') and relrowsecurity),
     'views',         (select count(*) from rels where relkind in ('v','m')),
     'policies',      (select count(*) from pols where not is_storage),
     'definer_functions', (select count(*) from dfns2),
     'definer_functions_not_graded', (select count(*) from dfns2 where not anon_exec and has_check)),
  'summary', jsonb_build_object(
     'critical', (select count(*) from findings where severity = 'critical'),
     'high',     (select count(*) from findings where severity = 'high'),
     'medium',   (select count(*) from findings where severity = 'medium'),
     'low',      (select count(*) from findings where severity = 'low'),
     'info',     (select count(*) from findings where severity = 'info')),
  'findings', (select coalesce(jsonb_agg(jsonb_build_object(
                  'check', check_id, 'severity', severity, 'object', object, 'detail', detail, 'fix', fix)
                order by array_position(array['critical','high','medium','low','info'], severity), object), '[]')
               from findings)
)::text as report;
