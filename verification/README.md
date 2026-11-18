# LaminaDB durability fault verification

This directory contains a fault-injection verification suite for LaminaDB's
three data-landing paths: **commit confirmation**, **checkpoint replacement**,
and **backup / restore**. It exists because a single "kill the process and see
whether it starts" run proves almost nothing: LaminaDB starts cleanly on a
journal whose acknowledged commit has been silently removed (proved by the
negative control in `harness/selfcheck.py`), so startup success cannot be the
oracle.

Everything here is derived from the documented format in `README.md` and
`PROJECT_SPEC.md`. The Go code was read to find the syscalls to target, but no
verification component imports or executes LaminaDB's own recovery code.

```
tracer/tracer.c        ptrace-based injector: counts durability syscalls,
                       freezes the process at a chosen boundary, then
                       kills / aborts / flips a byte / shortens the frame /
                       forces fsync to return EIO
harness/matrix.py      case list + CLI; writes results/<run>/matrix.{json,md}
harness/selfcheck.py   negative controls proving the harness can fail
harness/report.py      renders OBSERVATIONS.md from a run
run.sh                 build + self-checks + full matrix
harness/lib/lamina.py  HTTP client, process supervision
harness/lib/journalmodel.py   independent LMW1 frame parser + replay
harness/lib/imagemodel.py     independent .lmi envelope/image decoder+validator
harness/lib/oracle.py         independent START/REFUSE + expected-rows oracle
harness/lib/scenarios.py      scenario definitions (setup + trigger)
harness/lib/runner.py         executes one case, records raw evidence,
                              classifies from evidence only
harness/lib/corruptions.py    deterministic byte damage for rejection cases
```

## Running

```sh
# one command: build, run harness negative controls, run the whole matrix
verification/run.sh

# or step by step
go build -o bin/laminad ./cmd/laminad
cc -O2 -o verification/tracer/laminad-fault verification/tracer/tracer.c
python3 verification/harness/selfcheck.py          # prove the harness can fail
python3 verification/harness/matrix.py             # all 38 cases, 1 repeat
python3 verification/harness/matrix.py --repeat 3  # determinism check
python3 verification/harness/matrix.py --group commit
python3 verification/harness/matrix.py --case commit-kill-after-fsync
python3 verification/harness/matrix.py --list
```

Outputs land in `verification/results/<timestamp>/`:

```
matrix.json        machine-readable summary + every raw observation
matrix.md          one-line-per-case table
OBSERVATIONS.md    the human-auditable report (tables + findings)
cases/<case>/      record.json, tracer.jsonl, fault-snapshot/, post_fault/,
                   server.log, recovery.log
repeat/rN/         per-repeat evidence when --repeat is used
```

Reference runs are committed under `results/`: `results/run-final/` is the
canonical 3-repeat run of all 38 cases (repeat evidence archived as
`repeat-evidence.tar.gz`).

`matrix.py` records the binary and tracer SHA-256 in the summary so a result
set can be tied to exact artefacts.

## Why ptrace rather than SIGKILL from the client

A client-side `kill -9` races the server: the process may have finished the
commit, written the response, or written nothing, and the harness cannot tell
which. The tracer instead stops the target **at a chosen syscall boundary**
with `PTRACE_SYSCALL_INFO`, so the recorded boundary is exact:

- `kill-in:N:KIND` — the N-th matching syscall has been entered and has not
  executed. Bytes from that syscall are not in the file.
- `kill-after:N:KIND` — the N-th matching syscall returned; the process is
  frozen before executing the next user-space instruction. Bytes from that
  syscall are in the file.
- `abort-after:N:KIND` — same boundary, then SIGABRT, so the Go runtime's fatal
  path runs. This action does not freeze other goroutines (the runtime's fatal
  handler needs them), so any post-boundary work is racy *by construction*; the
  case is marked accordingly.
- `eio-after:N:KIND` — the syscall completed, then its return value is rewritten
  to `-EIO`; the process keeps running so the "must stop serving" contract can
  be observed.
- `torn-after:N:KIND` — the just-written frame is physically shortened to half a
  frame, simulating a media failure that completes a short write.
- `--corrupt-flip` — one byte inside the persisted frame (or renamed image) is
  flipped at the boundary.

Every counted syscall is logged with its path, file offset, length, and — for
journal writes — the frame's length/CRC/sequence/kind read directly out of the
target's memory. Immediately around the fault the tracer copies the raw bytes
of every watched file into the evidence directory using its own `pread(2)`.
Those copies are the byte-level record; the harness's parsers read them, not
LaminaDB.

## What each pivot is

| path | syscalls that matter | injected boundaries |
| --- | --- | --- |
| commit | `write(journal)` then `fsync(journal)` | kill-in write, kill-after write, kill-in fsync, kill-after fsync, abort-after fsync, EIO-at-fsync, byte-flip, torn frame, 40-row large commit |
| checkpoint | temp `write`+`fsync`, `rename`, directory `fsync` | kill after temp fsync, kill-in rename, kill-after rename, kill-after directory fsync, kill-after temp unlink, byte-flip after rename, kill-in second rename, acknowledged-then-SIGKILL control |
| backup / restore | source `GET /backup`; restore `write`+`fsync` header, directory `fsync`, temp image `write`+`fsync`, `rename` | kill-in header write, kill-after header fsync, kill-in image write, kill-after image fsync (fsync #3; #2 is the directory sync after header creation), kill-after restore rename, byte-flip install, stale digest |
| corruption rejection | — | bad CRC, zero length, sequence gap, truncated header, base-ahead journal, digest mismatch, wrong row type, bad version order, unknown relation, bad catalog sequence, unique violation, truncatable tail control |

## Classification vocabulary

The runner uses only recorded observations:

- **confirmed** — the client received a 200 for that specific request.
- **unconfirmed** — the client saw a transport death or 5xx, or the process died
  before the response. The bytes may or may not have survived.
- **must_refuse** — the on-disk bytes are not a valid state; startup must fail.

| label | meaning |
| --- | --- |
| `confirmed_and_persisted` | 200, and the payload is present after recovery |
| `unconfirmed_persisted` | no 200, payload present — permitted |
| `unconfirmed_absent` | no 200, payload absent — permitted |
| `BROKEN_confirmed_lost` | 200 but payload gone — a real defect |
| `BROKEN_acked_rows_lost` | a row acked before the fault disappeared |
| `confirmed_and_recovered` | checkpoint acked, image installed, rows equal journal replay |
| `recovered` | unconfirmed checkpoint, rows still equal journal replay |
| `refused_after_unconfirmed_checkpoint` | unconfirmed checkpoint left invalid bytes; refusal correct |
| `restore_complete` / `restore_incomplete` | restored rows equal / are a subset of the source image |
| `restore_not_installed` | zero-length journal and no checkpoint: starts as a fresh empty database, contains no backup data |
| `restore_left_refusable_state` | restore died with a partial install; startup must refuse |
| `refused_as_required` | damaged bytes rejected at startup |
| `BROKEN_silent_accept` | damaged bytes accepted |
| `accepted_cleanly` | truncatable tail; visible rows and reported tail match the model |

The full raw evidence for every case is in
`results/<run>/cases/<case>/artifacts/`, including the tracer JSONL, file
snapshots at the fault, the server's stderr, and `record.json`.

## Fidelity boundary (what this suite does not claim)

- Injection is at **syscall boundaries**, not at the block-device layer. A kill
  after `write(2)` but before `fsync(2)` leaves the bytes visible in the file
  image because the harness reads through the page cache of a live system. On a
  power loss those bytes might not survive. The matrix therefore models
  **process** crashes faithfully and **power** loss only for the relative
  ordering it can force (bytes present ⇒ fsync had completed); it does not
  simulate a volatile write cache.
- The harness filesystem here is `virtiofs` on `/workspace` (a container
  mapping to the host) with `overlayfs`/`tmpfs` options also available. `fsync`
  behaviour on those is not identical to a bare disk; `tracer/tracer.c` records
  the observed latency and the suite never asserts timing.
- Restore is exercised as a separate process into a brand-new directory. Each
  case also attempts a retry of the same `-restore` into that directory and
  records that it is refused (`restore_retry_same_dir_started = false`:
  restore requires a new directory). Layering a valid restore onto a partially
  installed directory and concurrent restores are out of scope.
- A zero-length `journal.lmw` is treated by the model as a fresh journal
  (that is LaminaDB's documented behaviour on open), so a restore killed
  during header creation is reported as `restore_not_installed`, not as a
  refusal.
- Corruption tests inject damage while the server is stopped. Damage that
  happens while a live instance holds the journal open is covered only through
  the `--corrupt-flip` boundary.
- Unique-index and multi-relation atomicity are only partially exercised; the
  matrix uses one relation and, in one case, a synthetic index in the image.
