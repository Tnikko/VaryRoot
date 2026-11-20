#!/usr/bin/env bash
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
echo "Measurement workspace: $work" >&2
mkdir "$work/src" "$work/ql"
cp "$repo"/tests/fixtures/frontend/{accesses.cpp,reviewed.c} "$work/src/"
cp "$repo"/tools/alignment07/{sites.ql,qlpack.yml,codeql-pack.lock.yml} "$work/ql/"
if [[ ${1:-} == columns ]]; then
  python3 "$repo/tools/alignment07/probe_columns.py" "$work/src/reviewed.c"
fi
cd "$work/src"
codeql=${CODEQL:-codeql}
"$codeql" database create "$work/db" --language=cpp --source-root=. --command='sh -c "gcc -c reviewed.c && g++ -c accesses.cpp"' -j1
cd "$work/ql"
packs=()
if [[ -n ${CODEQL_PACKS:-} ]]; then
  packs=(--additional-packs="$CODEQL_PACKS")
fi

"$codeql" query run "${packs[@]}" sites.ql --database="$work/db" --output="$work/sites.bqrs" -j1
"$codeql" bqrs decode "$work/sites.bqrs" --format=csv > "$work/sites.csv"
cat "$work/sites.csv"
