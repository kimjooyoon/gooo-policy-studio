#!/bin/sh
# Runs one synthetic bounds comparison, retained replay and private explanation.
set -eu
umask 077

work=
calls=0
finished=false
fail() {
    printf '{"schema":"policy-impact-bounds-kit-demo/v1","status":"error","code":"%s","work_directory":"%s","product_calls":%s,"simulation":true}\n' "$1" "$work" "$calls"
    exit 2
}
on_exit() {
    result=$?
    if [ "$finished" != true ] && [ "$result" -ne 0 ] && [ -n "$work" ]; then
        printf '%s\n' 'Demo stopped; private reports and diagnostics were retained.' >&2
        printf '%s\n' "$work" >&2
    fi
}
trap on_exit 0
trap 'fail INTERRUPTED' 1 2 15

case $# in
    0) ;;
    1) case $1 in
        --help|-h) printf '%s\n' 'Usage: ./try-demo.sh' 'Use an extracted bounds-profile kit: compare row501, delete private copied inputs, replay, then save a private HTML explanation.' 'Uses standard shell/tools; no Go/compiler/Python/server/account/token/network.' 'Historical consistency is not a current execution grant.'; exit 0 ;;
        *) fail USAGE_INVALID ;;
       esac ;;
    *) fail USAGE_INVALID ;;
esac

kit=$(CDPATH= cd -P "$(dirname "$0")" && pwd -P) || fail KIT_DIRECTORY_INVALID
system=$(uname -s) || fail PLATFORM_UNAVAILABLE
machine=$(uname -m) || fail PLATFORM_UNAVAILABLE
case "$system/$machine" in
    Darwin/arm64) host=darwin/arm64 ;;
    Linux/x86_64) host=linux/amd64 ;;
    *) fail PLATFORM_UNSUPPORTED ;;
esac

# Bound and validate every listed name before allowing checksum tools to read it.
[ -f "$kit/SHA256SUMS" ] && [ ! -L "$kit/SHA256SUMS" ] || fail CHECKSUM_LIST_INVALID
list_size=$(wc -c < "$kit/SHA256SUMS") || fail CHECKSUM_LIST_INVALID
[ "$list_size" -le 4194304 ] || fail CHECKSUM_LIST_INVALID
awk '
BEGIN { n=0; bad=0 }
{
  h=substr($0,1,64); sep=substr($0,65,2); p=substr($0,67);
  if (length($0)>1024 || length(h)!=64 || h !~ /^[0-9a-f]+$/ || sep!="  " || p !~ /^[A-Za-z0-9._\/-]+$/ || p ~ /^\// || p ~ /\/$/ || p ~ /(^|\/)\.\.?($|\/)/ || p ~ /\/\// || p=="SHA256SUMS" || seen[p]++) bad=1;
  n++;
  if (n>4096) exit 1;
}
END { if (n<20 || bad) exit 1 }
' "$kit/SHA256SUMS" || fail CHECKSUM_LIST_INVALID
for required in bin/policy-impact try-demo.sh target.txt buildinfo.txt manifest.json \
    seeds/case-row-501.json seeds/artifact-row-501.json \
    seeds/policy-before-upper-1000.json seeds/policy-after-upper-500.json \
    notices/LICENSE notices/Go-LICENSE notices/LICENSE-REA notices/NOTICE.md \
    docs/artifact-bounds-first-use.md docs/artifact-int64-bounds.md \
    docs/artifact-policy-explain.md docs/artifact-policy-impact.md docs/artifact-policy-replay.md
do
    awk -v p="$required" 'substr($0,67)==p {found++} END {if(found!=1) exit 1}' "$kit/SHA256SUMS" || fail CHECKSUM_LIST_INVALID
done
# Static extraction preflight; this does not claim an atomic installer against
# another process changing files after inspection. Reject FIFOs and symlinks.
total_bytes=0
while IFS= read -r line; do
    relative=${line#*  }
    current=$kit
    remaining=$relative
    while :; do
        component=${remaining%%/*}
        current=$current/$component
        [ ! -L "$current" ] || fail CHECKSUM_MEMBER_INVALID
        if [ "$component" = "$remaining" ]; then
            [ -f "$current" ] || fail CHECKSUM_MEMBER_INVALID
            break
        fi
        [ -d "$current" ] || fail CHECKSUM_MEMBER_INVALID
        remaining=${remaining#*/}
    done
    size=$(wc -c < "$current") || fail CHECKSUM_MEMBER_INVALID
    case "$relative" in bin/policy-impact) cap=67108864 ;; *) cap=16777216 ;; esac
    [ "$size" -le "$cap" ] || fail CHECKSUM_MEMBER_TOO_LARGE
    total_bytes=$((total_bytes + size))
    [ "$total_bytes" -le 268435456 ] || fail KIT_TOO_LARGE
done < "$kit/SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
    hash_kind=sha256sum
    (CDPATH= cd -P "$kit" && sha256sum -c SHA256SUMS >/dev/null 2>&1) || fail CHECKSUM_MISMATCH
elif command -v shasum >/dev/null 2>&1; then
    hash_kind=shasum
    (CDPATH= cd -P "$kit" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) || fail CHECKSUM_MISMATCH
else
    fail CHECKSUM_TOOL_MISSING
fi
target_size=$(wc -c < "$kit/target.txt") || fail TARGET_INVALID
[ "$target_size" -le 64 ] || fail TARGET_INVALID
target=$(cat "$kit/target.txt") || fail TARGET_INVALID
[ "$target" = "$host" ] || fail PLATFORM_MISMATCH
awk '
/^  "schema": "policy-impact-kit\/v2",?$/ { schema++ }
/^  "profile": "artifact-bounds\/v1",?$/ { profile++ }
END { if (schema!=1 || profile!=1) exit 1 }
' "$kit/manifest.json" || fail PROFILE_INVALID

hash_file() {
    if [ "$hash_kind" = sha256sum ]; then
        checksum=$(sha256sum "$1") || return 1
    else
        checksum=$(shasum -a 256 "$1") || return 1
    fi
    printf '%s\n' "$checksum" | awk 'NF { if (length($1)!=64 || $1 !~ /^[0-9a-f]+$/ || n++) exit 1; print $1 } END { if (n!=1) exit 1 }'
}
[ -x "$kit/bin/policy-impact" ] || fail BINARY_INVALID
work=$(mktemp -d /tmp/gooo-policy-impact-bounds.XXXXXXXX) || fail PRIVATE_DIRECTORY_FAILED
chmod 700 "$work" || fail PRIVATE_DIRECTORY_FAILED
work=$(CDPATH= cd -P "$work" && pwd -P) || fail PRIVATE_DIRECTORY_FAILED
# No caller-selected work/deletion path; generated paths need no JSON escaping.
case "$work" in
    /tmp/gooo-policy-impact-bounds.*|/private/tmp/gooo-policy-impact-bounds.*) ;;
    *) fail PRIVATE_DIRECTORY_INVALID ;;
esac
case "$work" in *[!A-Za-z0-9._/-]*) fail PRIVATE_DIRECTORY_INVALID ;; esac

digest_record() {
    [ -f "$2" ] && [ ! -L "$2" ] || fail DIGEST_FAILED
    digest=$(hash_file "$2") || fail DIGEST_FAILED
    printf '%s\t%s\n' "$1" "$digest" >> "$work/digests.tsv"
}
digest_record binary_before "$kit/bin/policy-impact"
for name in case-row-501.json artifact-row-501.json policy-before-upper-1000.json policy-after-upper-500.json; do
    cp "$kit/seeds/$name" "$work/$name" || fail PRIVATE_INPUT_FAILED
    chmod 600 "$work/$name" || fail PRIVATE_INPUT_FAILED
done
placeholder=/replace-with-your-private-directory/artifact-row-501.json
count=$(awk -v p="$placeholder" '{ rest=$0; while ((i=index(rest,p))>0) { n++; rest=substr(rest,i+length(p)) } } END { print n+0 }' "$work/case-row-501.json") || fail CASE_TEMPLATE_INVALID
[ "$count" -eq 1 ] || fail CASE_TEMPLATE_INVALID
sed "s|/replace-with-your-private-directory/artifact-row-501[.]json|$work/artifact-row-501.json|" "$work/case-row-501.json" > "$work/case.updated.json" || fail CASE_TEMPLATE_INVALID
mv "$work/case.updated.json" "$work/case-row-501.json" || fail CASE_TEMPLATE_INVALID
chmod 600 "$work/case-row-501.json" || fail PRIVATE_INPUT_FAILED
for name in case-row-501.json artifact-row-501.json policy-before-upper-1000.json policy-after-upper-500.json; do
    digest_record "input_$name" "$work/$name"
done

invoke() {
    index=$1; action=$2; direction=$3; name=$4
    shift 4
    : > "$work/$name.summary.json" || fail DIAGNOSTIC_FILE_FAILED
    : > "$work/$name.stderr" || fail DIAGNOSTIC_FILE_FAILED
    chmod 600 "$work/$name.summary.json" "$work/$name.stderr" || fail DIAGNOSTIC_FILE_FAILED
    printf '%s\t%s\t%s\tstarted\t-\n' "$index" "$action" "$direction" >> "$work/product-calls.tsv"
    calls=$((calls + 1))
    if "$kit/bin/policy-impact" "$@" > "$work/$name.summary.json" 2> "$work/$name.stderr"; then rc=0; else rc=$?; fi
    printf '%s\t%s\t%s\tcompleted\t%s\n' "$index" "$action" "$direction" "$rc" >> "$work/product-calls.tsv"
    digest_record "$name.summary" "$work/$name.summary.json"
    [ "$rc" -eq 0 ] || fail PRODUCT_CALL_FAILED
}
invoke 1 compare newly_denied 01-compare compare \
    --case "$work/case-row-501.json" --before "$work/policy-before-upper-1000.json" \
    --after "$work/policy-after-upper-500.json" --report "$work/comparison.report.json"
digest_record report_before_replay "$work/comparison.report.json"
# Delete only this invocation's four known copies; retain report, seeds and binary.
for name in case-row-501.json artifact-row-501.json policy-before-upper-1000.json policy-after-upper-500.json; do
    rm "$work/$name" || fail INPUT_DELETE_FAILED
    [ ! -e "$work/$name" ] && [ ! -L "$work/$name" ] || fail INPUT_DELETE_FAILED
    printf '%s\n' "$name" >> "$work/inputs.deleted"
done
invoke 2 replay newly_denied 02-replay replay --report "$work/comparison.report.json"
digest_record report_after_replay "$work/comparison.report.json"
digest_record report_before_explain "$work/comparison.report.json"
invoke 3 explain newly_denied 03-explain explain --report "$work/comparison.report.json" --output "$work/explanation.html"
digest_record report_after_explain "$work/comparison.report.json"
digest_record explanation_html "$work/explanation.html"
digest_record binary_after "$kit/bin/policy-impact"
finished=true
printf '{"schema":"policy-impact-bounds-kit-demo/v1","status":"completed","work_directory":"%s","product_calls":3,"simulation":true}\n' "$work"
