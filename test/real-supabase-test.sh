#!/usr/bin/env bash
# Runs audit.sql against a REAL local Supabase stack (Supabase CLI + Docker):
#   1) on a fresh project      -> report-empty.json  (should have zero findings)
#   2) after loading the demo  -> report-vuln.json   (should catch all planted issues)
# Requirements: Docker running, Node.js (for npx). No psql needed, no dashboard.
# Usage (from a repo checkout, or with the three files in one folder): bash test/real-supabase-test.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
pick() { for c in "$@"; do [ -f "$c" ] && { echo "$c"; return; }; done; }
AUDIT=$(pick "$HERE/audit.sql" "$HERE/../audit.sql")
VULN=$(pick "$HERE/vulnerable_app.sql" "$HERE/test/vulnerable_app.sql")
[ -n "$AUDIT" ] && [ -n "$VULN" ] || { echo "Can't find audit.sql and vulnerable_app.sql"; exit 1; }

WORK="$HERE/sb-local-test"
mkdir -p "$WORK" && cd "$WORK"
SB="npx -y supabase@latest"

echo ">> Initializing local Supabase project"
[ -f supabase/config.toml ] || $SB init >/dev/null
# Move every port from 543xx to 553xx so this never collides with other local Supabase projects
sed -i.bak -E 's/^([[:space:]]*(port|shadow_port)[[:space:]]*=[[:space:]]*)543([0-9]{2})/\1553\3/' supabase/config.toml

echo ">> Starting Supabase (first run downloads images, a few minutes)"
$SB start -x studio,imgproxy,edge-runtime,logflare,vector,mailpit,realtime,supavisor,postgres-meta

PROJECT_ID=$(sed -nE 's/^project_id[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' supabase/config.toml)
DB="supabase_db_${PROJECT_ID}"   # this test project only, never your other local projects
docker ps --format '{{.Names}}' | grep -qx "$DB" || { echo "Container $DB is not running"; exit 1; }
PSQL="docker exec -i $DB psql -U postgres -d postgres -v ON_ERROR_STOP=1"

audit() {  # read-only run, raw JSON out
  { echo "begin transaction read only;"; cat "$AUDIT"; echo "rollback;"; } | $PSQL -At -q
}

echo ">> 1/2 Auditing the empty project"
audit > "$HERE/report-empty.json"

echo ">> 2/2 Loading the vulnerable demo app and auditing again"
$PSQL -q < "$VULN"
audit > "$HERE/report-vuln.json"

echo
echo "Done. Summaries:"
for f in report-empty.json report-vuln.json; do
  printf '  %-18s ' "$f"
  node -e 'const r=require(process.argv[1]); console.log(JSON.stringify(r.summary))' "$HERE/$f"
done
echo
echo "Send both report-*.json files back. To stop and delete the local stack:"
echo "  cd \"$WORK\" && $SB stop --no-backup"
