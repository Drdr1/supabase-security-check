# Supabase Security Check

A free, read-only check that finds the places where your Supabase data is reachable by people who shouldn't see it: tables without Row Level Security, policies that allow everything, views that bypass RLS, exposed `auth.users`, risky `SECURITY DEFINER` functions, public buckets and more.

It's a single `SELECT` statement. You run it in your own SQL editor, it reads your schema (never your rows), and you get one JSON report with a severity, a plain-English explanation and a suggested SQL fix for every finding.

**Use it online:** [derops.dev/check](https://derops.dev/check) grades the report (A to F) and shows the findings in your browser. Nothing is uploaded.

## Why this matters

Your Supabase anon key ships inside your frontend; anyone can copy it from the browser. With it, they can call your REST API directly. Row Level Security and function privileges are the only things deciding what they get back. Apps built quickly, especially with AI builders like Lovable or Bolt, often ship with gaps: RLS left off on one table, a `using (true)` policy from a tutorial, a view that silently ignores RLS.

## Run it

### Supabase dashboard

1. Open **SQL Editor** and create a new query.
2. Paste the contents of [`audit.sql`](audit.sql) and click **Run**.
3. Copy the single `report` cell and paste it at [derops.dev/check](https://derops.dev/check), or read the JSON directly.

### Terminal

Use the **Session pooler** connection string from your project's **Connect** dialog:

```bash
{ echo "begin transaction read only;"; cat audit.sql; echo "rollback;"; } \
  | psql "$DATABASE_URL" -At -q > report.json
```

Wrapping it in a read-only transaction means Postgres itself rejects any write.

### Local Supabase (CLI)

```bash
docker exec -i supabase_db_<project_id> psql -U postgres -d postgres -At -q < audit.sql > report.json
```

## What it checks

| Check | Severity | What it means |
|---|---|---|
| `rls_disabled` | critical / high | A table the API can reach has RLS turned off |
| `auth_users_exposed` | critical | A view or materialized view reads `auth.users` and is reachable through the API |
| `policy_open_read` | critical to low | `using (true)` on a readable table. Critical when anon can read sensitive-looking columns, low for owner-less reference data read by signed-in users |
| `policy_open_write` | high to low | Anyone (or any signed-in user) can insert, modify or delete rows, or upload to Storage |
| `policy_user_metadata` | high | A policy trusts `user_metadata`, which users can edit themselves |
| `view_bypasses_rls` | high / medium | A view without `security_invoker`, so RLS underneath is ignored |
| `security_definer_function` | high to low | A `SECURITY DEFINER` function callable via `/rpc`, graded by who can call it, whether it writes, and whether its body checks the caller (following helper calls to any depth) |
| `function_search_path_mutable` | medium | A definer function without a fixed `search_path` |
| `matview_exposed` | high / medium | A materialized view (no RLS possible) reachable through the API |
| `public_bucket` | high / medium | A public Storage bucket; high when its name suggests private documents |
| `policy_uid_not_wrapped` | low | `auth.uid()` evaluated per row instead of once per query (performance) |
| `extension_in_api_schema` | low | An extension installed in an API-exposed schema |
| `rls_no_policy` | info | RLS on with no policies, so the API can't use the table |

The grade on the web page: **F** with any critical finding, **D** with two or more high, **C** with one high, **B** with only medium, **A** otherwise.

## What it doesn't check

It reads the database catalog. It can't see your app code, edge functions, auth settings, or the logic inside a policy beyond the patterns above. A function "checks the caller" if its body references `auth.uid()`, `auth.jwt()` or `auth.role()`, directly or through helpers; whether that check is *correct* needs a human. A clean grade means no catalog-level exposure, not "fully secure". Treat the suggested fixes as starting points and test them before production.

Only run it on projects you own or have permission to assess.

## Tests

The query is tested against a Supabase-like Postgres with a deliberately vulnerable app ([`test/vulnerable_app.sql`](test/vulnerable_app.sql)). Every planted issue must be found with the expected severity, correctly secured objects must produce nothing, an empty project must produce zero findings, and the query must run inside a read-only transaction.

```bash
PGHOST=localhost PGUSER=postgres ./test/run.sh
```

[`test/real-supabase-test.sh`](test/real-supabase-test.sh) runs the same check against the real Supabase stack via the Supabase CLI and Docker.

## Web page

[`web/check.template.html`](web/check.template.html) is the source of the report page; `python3 web/build.py` embeds the current `audit.sql` and the [example report](examples/sample-report.json) into `web/dist/check.html`, a single self-contained file.

## Need help fixing what it found?

I'm Ahmed Darder ([DerOps](https://derops.dev)), a CKA-certified DevOps engineer who reviews Supabase security for founders and small teams. Reviews and fixes are booked through Upwork; details at [derops.dev/check](https://derops.dev/check#fix). For the six most common RLS mistakes with working exploits and fixes, see the [Supabase RLS casebook](https://github.com/Drdr1/supabase-rls-casebook).

## License

MIT
