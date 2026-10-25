#!/usr/bin/env bash
set -euo pipefail
bin="${1:?expected compiled auth_alert_export path}"
d=$(mktemp -d)
trap 'rm -rf -- "$d"' EXIT
printf '1760000000000\t1\t192.0.2.11\tuser1\n' > "$d/ordinary.tsv"
"$bin" "$d/ordinary.tsv" "$d/ordinary.csv" > "$d/ordinary.result"
grep -Fxq 'AUTH_CSV_TRANSITIONS=0' "$d/ordinary.result"
test "$(wc -l < "$d/ordinary.csv")" -eq 1
echo 'PASS isolated authentication failure does not alert'
for i in 0 1 2 3 4; do
    printf '%s\t1\t192.0.2.11\tuser1\n' "$((1760000000000+i*1000))"
done > "$d/burst.tsv"
"$bin" "$d/burst.tsv" "$d/burst.csv" > "$d/burst.result"
grep -Fxq 'AUTH_CSV_TRANSITIONS=1' "$d/burst.result"
grep -Fq ',alert,1,1,0,0' "$d/burst.csv"
echo 'PASS fifth failure creates one aggregate alert transition'
printf '1760000120000\t0\t192.0.2.11\tuser1\n' >> "$d/burst.tsv"
"$bin" "$d/burst.tsv" "$d/recovery.csv" > "$d/recovery.result"
grep -Fxq 'AUTH_CSV_TRANSITIONS=2' "$d/recovery.result"
grep -Fq ',recovery,0,0,1,1' "$d/recovery.csv"
echo 'PASS later event observes recovery'
"$bin" "$d/burst.tsv" "$d/repeated.csv" > /dev/null
cmp -s "$d/recovery.csv" "$d/repeated.csv"
echo 'PASS full historical replay is deterministic'
printf 'malformed\n' > "$d/bad.tsv"
if "$bin" "$d/bad.tsv" "$d/bad.csv" > /dev/null 2>&1; then
    echo 'ERROR malformed input accepted' >&2; exit 1
fi
test ! -e "$d/bad.csv"
echo 'PASS malformed input fails closed without final CSV'
if grep -Eq '192\.0\.2|user1' "$d/recovery.csv"; then
    echo 'ERROR private identifier leaked to CSV' >&2; exit 1
fi
echo 'PASS CSV omits IP and username'
echo 'AUTH_ALERT_CSV_TESTS=6 PASS'
