#!/usr/bin/env bash
# Regression test: runs audit.sql against a Supabase-like Postgres and checks the findings.
# Usage: PGHOST=... PGPORT=... PGUSER=postgres ./test/run.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PSQL="psql -v ON_ERROR_STOP=1 -q"

findings() {  # $1 = database
  $PSQL -d "$1" -At -f audit.sql | python3 -c '
import json, sys
for f in json.load(sys.stdin)["findings"]:
    print(f["severity"], f["check"], f["object"])'
}

fresh() {
  $PSQL -d postgres -c "drop database if exists $1" -c "create database $1" 2>/dev/null
  $PSQL -d "$1" -f test/supabase_shim.sql
}

fail=0

echo "1) vulnerable app: every planted issue must be found, nothing extra"
fresh sscheck_vuln
$PSQL -d sscheck_vuln -f test/vulnerable_app.sql
if diff <(sort test/expected.txt) <(findings sscheck_vuln | sort); then
  echo "   PASS"
else
  echo "   FAIL (diff above: < expected, > actual)"; fail=1
fi

echo "2) empty project: no findings"
fresh sscheck_empty
out=$(findings sscheck_empty)
if [ -z "$out" ]; then echo "   PASS"; else echo "   FAIL:"; echo "$out"; fail=1; fi

echo "3) read-only: audit runs inside a READ ONLY transaction"
if { echo "begin transaction read only;"; cat audit.sql; echo "commit;"; } \
     | $PSQL -d sscheck_vuln -At >/dev/null; then
  echo "   PASS"
else
  echo "   FAIL"; fail=1
fi

$PSQL -d postgres -c "drop database sscheck_vuln" -c "drop database sscheck_empty"
exit $fail
