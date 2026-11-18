#!/bin/sh
# Build everything the durability verification needs and run it end to end.
#
#   verification/run.sh                    # self-checks + full matrix, 3 repeats
#   verification/run.sh --quick            # self-checks + one repeat per case
#   verification/run.sh --group commit     # one persistence path
#
# Requires Go (1.25+) and a C compiler. No network access is needed; the Go
# module has no external dependencies.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project=$(dirname "$here")
cd "$project"

: "${GO:=go}"
command -v "$GO" >/dev/null 2>&1 || { echo "Go not found; set GO=/path/to/go" >&2; exit 2; }
# Some images provide a `cc` wrapper that refuses non-interactive use; prefer a
# real compiler when one is present.
CC_BIN=${CC:-}
if [ -z "$CC_BIN" ]; then
    for candidate in cc gcc clang; do
        path=$(command -v "$candidate" 2>/dev/null || true)
        if [ -n "$path" ] && "$path" --version >/dev/null 2>&1; then
            CC_BIN=$path
            break
        fi
    done
fi
[ -n "$CC_BIN" ] || { echo "no working C compiler; set CC=/path/to/cc" >&2; exit 2; }

echo "[build] laminad"
"$GO" build -trimpath -o bin/laminad ./cmd/laminad
echo "[build] laminad-fault"
"$CC_BIN" -O2 -o verification/tracer/laminad-fault verification/tracer/tracer.c

echo "[selfcheck] proving the harness can fail"
python3 verification/harness/selfcheck.py \
    "$project/bin/laminad" "$project/verification/tracer/laminad-fault" \
    "$project/verification/results/selfcheck"

run_root="$project/verification/results/$(date +%Y%m%dT%H%M%S)"
case "${1:-}" in
    --quick)
        shift
        echo "[matrix] one repeat into $run_root"
        python3 verification/harness/matrix.py --run-root "$run_root" "$@"
        ;;
    --group)
        shift
        group=${1:?--group needs a value}
        shift
        echo "[matrix] group '$group' into $run_root"
        python3 verification/harness/matrix.py --run-root "$run_root" \
            --group "$group" --repeat 3 "$@"
        ;;
    *)
        echo "[matrix] 3 repeats into $run_root"
        python3 verification/harness/matrix.py --run-root "$run_root" --repeat 3 "$@"
        ;;
esac
echo "[done] $run_root/OBSERVATIONS.md"
