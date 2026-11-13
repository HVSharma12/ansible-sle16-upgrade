#!/usr/bin/env bash
# Run the role three times against one inventory: normal, again, and in check mode.
# Passes when every run reports changed=0 and the three JSON reports are equal apart from collected_at and the
# free space counters, which move on a live host.
# Usage: tests/e2e/repeat.sh <inventory> <workdir> [ansible-playbook args...]
set -u
inventory=$1 workdir=$2
shift 2
here=$(cd "$(dirname "$0")/.." && pwd)
playbook=${ANSIBLE_PLAYBOOK:-ansible-playbook}
mkdir -p "$workdir"
cp "$here/playbooks/tests_default.yml" "$workdir/"
fail=0
for run in first second check; do
    extra=()
    [ "$run" = check ] && extra=(--check)
    log="$workdir/$run.log"
    (cd "$workdir" && "$playbook" -i "$inventory" tests_default.yml "${extra[@]}" "$@") > "$log" 2>&1
    rc=$?
    recap=$(grep -A20 '^PLAY RECAP' "$log" | grep -E 'ok=' )
    echo "$run: rc=$rc $recap"
    [ "$rc" -eq 0 ] || fail=1
    echo "$recap" | grep -qv 'changed=0' && fail=1
    for json in "$workdir"/sle16-upgrade-reports/*.json; do
        jq -S 'del(.collected_at, .facts.storage.free_mb)' "$json" > "$workdir/$run.$(basename "$json")"
    done
done
for json in "$workdir"/first.*.json; do
    host=${json#"$workdir"/first.}
    for run in second check; do
        if cmp -s "$json" "$workdir/$run.$host"; then
            echo "same report: first = $run ($host)"
        else
            echo "DIFFERENT report: first != $run ($host)"
            diff "$json" "$workdir/$run.$host" | head -20
            fail=1
        fi
    done
done
[ "$fail" -eq 0 ] && echo "PASS repeat" || echo "FAIL repeat"
exit "$fail"
