-- A deliberately vulnerable demo app. Each object is labelled with the finding it should trigger.
-- Objects marked CLEAN must produce no high/critical findings.

-- rls_disabled (critical): anon can read and write everything
create table public.profiles (id uuid primary key, full_name text, email text, phone text);

-- policy_always_true (high): anon can read every order
create table public.orders (id serial primary key, user_id uuid, total numeric, address text);
alter table public.orders enable row level security;
create policy "orders readable" on public.orders for select using (true);

-- policy_always_true (medium): any logged-in user reads every note
create table public.notes (id serial primary key, user_id uuid, body text);
alter table public.notes enable row level security;
create policy "notes for users" on public.notes for select to authenticated using (true);

-- policy_always_true write (high): anyone can insert
create table public.feedback (id serial primary key, message text);
alter table public.feedback enable row level security;
create policy "anyone can submit" on public.feedback for insert to anon, authenticated with check (true);

-- policy_user_metadata (high): user_metadata is editable by the user themselves
create table public.documents (id serial primary key, title text);
alter table public.documents enable row level security;
create policy "admins read docs" on public.documents for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

-- CLEAN: correct owner-scoped policies (wrapped auth.uid())
create table public.messages (id serial primary key, user_id uuid not null, body text);
alter table public.messages enable row level security;
create policy "own messages" on public.messages for select to authenticated
  using (user_id = (select auth.uid()));
create policy "send own" on public.messages for insert to authenticated
  with check (user_id = (select auth.uid()));

-- policy_uid_not_wrapped (low, performance only)
create table public.tasks (id serial primary key, user_id uuid, title text);
alter table public.tasks enable row level security;
create policy "own tasks" on public.tasks for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- rls_no_policy (info): locked down, nobody but service_role can use it
create table public.audit_log (id serial primary key, event text);
alter table public.audit_log enable row level security;

-- auth_users_exposed (critical): view over auth.users in the API schema
create view public.user_emails as select id, email from auth.users;

-- view_bypasses_rls (high): view runs as owner, ignores RLS on orders
create view public.order_summary as select user_id, sum(total) as spent from public.orders group by user_id;

-- CLEAN: view that respects RLS
create view public.my_messages with (security_invoker = true) as select * from public.messages;

-- matview_exposed (medium)
create materialized view public.order_stats as select count(*) as n from public.orders;

-- security_definer_function (high) + function_search_path_mutable
create function public.get_all_profiles() returns setof public.profiles
  language sql security definer as $$ select * from public.profiles $$;

-- CLEAN: definer function locked to service_role with fixed search_path
create function public.admin_purge() returns void
  language sql security definer set search_path = '' as $$ delete from public.audit_log $$;
revoke execute on function public.admin_purge() from public, anon, authenticated;

-- CLEAN: invoker function
create function public.add(a int, b int) returns int language sql immutable as $$ select a + b $$;

-- security_definer_function (high): anon can call it, it writes, nothing checks the caller
create function public.reset_order(order_id int) returns void
  language sql security definer set search_path = '' as $$ update public.orders set total = 0 where id = order_id $$;

-- security_definer_function (low): anon can call it, but it checks the caller
create function public.get_my_order(order_id int) returns setof public.orders
  language sql security definer set search_path = ''
  as $$ select * from public.orders where id = order_id and user_id = (select auth.uid()) $$;

-- security_definer_function (low): anon can call it, gated by a token parameter (public form)
create function public.submit_by_token(form_token text, msg text) returns void
  language sql security definer set search_path = ''
  as $$ insert into public.feedback (message) select msg where form_token = 'expected' $$;

-- security_definer_function (medium): signed-in only, but no check on who is calling
create function public.all_notes() returns setof public.notes
  language sql security definer set search_path = '' as $$ select * from public.notes $$;
revoke execute on function public.all_notes() from public, anon;

-- CLEAN: signed-in only helper that checks the caller (typical RLS helper)
create function public.is_owner(uid uuid) returns boolean
  language sql stable security definer set search_path = '' as $$ select uid = (select auth.uid()) $$;
revoke execute on function public.is_owner(uuid) from public, anon;

-- CLEAN: signed-in only, checks the caller through the helper above
create function public.my_tasks() returns setof public.tasks
  language sql security definer set search_path = ''
  as $$ select * from public.tasks t where public.is_owner(t.user_id) $$;
revoke execute on function public.my_tasks() from public, anon;

-- CLEAN: two hops to the auth check (close_task -> assert_owner -> is_owner -> auth.uid())
create function public.assert_owner(uid uuid) returns void
  language plpgsql stable security definer set search_path = ''
  as $$ begin if not public.is_owner(uid) then raise exception 'not allowed'; end if; end $$;
revoke execute on function public.assert_owner(uuid) from public, anon;
create function public.close_task(task_id int) returns void
  language plpgsql security definer set search_path = ''
  as $$ declare owner uuid;
     begin
       select t.user_id into owner from public.tasks t where t.id = task_id;
       perform public.assert_owner(owner);
       delete from public.tasks where id = task_id;
     end $$;
revoke execute on function public.close_task(int) from public, anon;

-- policy_open_read (low): shared reference data, no owner column
create table public.countries (code text primary key, name text);
alter table public.countries enable row level security;
create policy "countries readable" on public.countries for select to authenticated using (true);

-- public_bucket (medium)
insert into storage.buckets (id, name, public) values ('invoices', 'invoices', true), ('avatars', 'avatars', false);

-- policy_always_true on storage (high): anyone can upload anywhere
create policy "anyone uploads" on storage.objects for insert to anon with check (true);
