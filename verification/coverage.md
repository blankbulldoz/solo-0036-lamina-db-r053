# Coverage and known gaps

This file states what the matrix actually establishes and what it does not.
It should be read together with `README.md` and the generated
`results/<run>/matrix.md`.

## Covered

### Commit confirmation (`--group commit`)

| boundary | what the bytes say | required outcome | case |
| --- | --- | --- | --- |
| before `write` executes | no frame | not confirmed, no row | `commit-kill-in-write` |
| after `write`, before `fsync` | frame in page cache | not confirmed; row may appear | `commit-kill-after-write` |
| at `fsync` entry | frame written | same as above | `commit-kill-in-fsync` |
| after `fsync` returns | frame durable | not confirmed (no 200 yet); row must appear | `commit-kill-after-fsync` |
| SIGABRT after `fsync` | frame durable | runtime dies without ack; row must appear | `commit-abort-after-fsync` |
| `fsync` returns EIO | frame written, durability unknown | 503, instance stops serving, no 200 | `commit-eio-at-fsync` |
| byte flip after `write` | frame CRC invalid | startup must refuse | `commit-corrupt-after-write` |
| torn frame (half written) | incomplete tail | startup truncates tail, row absent, no 200 | `commit-torn-after-write` |
| 40-row commit after `write` | one frame | atomic: all 40 or none | `commit-multi-frame-after-write` |
| acknowledged then SIGKILL | none pending | rows survive | `commit-baseline-ack-then-kill` |

The acknowledged-before-fault rows from `setup` are compared on every commit
case (`acked_rows_present`), and the independent oracle also asserts that every
row durable at the journal's highest commit sequence is visible
(`durable_floor_rows_present`).

### Checkpoint replacement (`--group checkpoint`)

`POST /checkpoint` = temp write → fsync(temp) → rename → fsync(dir).

| boundary | expected | case |
| --- | --- | --- |
| after temp fsync, before rename | old checkpoint authoritative; journal covers suffix | `checkpoint-kill-after-temp-fsync` |
| at rename entry | same | `checkpoint-kill-in-rename` |
| after rename, before dir fsync | new image named; may or may not be durable | `checkpoint-kill-after-rename` |
| after dir fsync | replacement durable, response not sent | `checkpoint-kill-after-dir-fsync` |
| byte flip in renamed image | startup refuses (no silent journal-only fallback) | `checkpoint-corrupt-after-rename` |
| after temp unlink | only the renamed checkpoint survives | `checkpoint-kill-after-unlink-temp` |
| two checkpoints, kill at second rename | first replacement intact | `checkpoint-twice-kill-in-second-rename` |
| checkpoint 200 then SIGKILL | image installed and equals journal replay | `checkpoint-baseline-ack-then-kill` |

Every checkpoint case compares the recovered rows to an independent replay of
the journal at the observed head (`rows_equal_journal_replay`).

### Backup and restore (`--group backup`, `--group restore`)

- `backup-frozen-while-source-writes`: a commit lands concurrently with
`GET /backup`; the returned image is decoded independently, its rows are
compared to journal replay at its own sequence, and a second backup after a
later source commit is shown to include the new row while the first file's
bytes are unchanged (`backup_bytes_stable_after_source_write`).
- Restore faults: killed before the journal header, after header fsync, at the
temp image write, after temp image fsync, after the restore rename, byte flip
in the installed image, and a tampered envelope digest. Each attempts a
retry into the same directory and records whether it is refused
(`restore_retry_same_dir_started`, currently `false` — restore requires a new
directory).

The source backup file is never written by LaminaDB during these cases; the
harness copies it into the evidence directory and restores from that copy. The
self-check `harness-source-not-mutated` proves the copy's digest is unchanged.

### Corruption rejection (`--group corruption`)

Eleven independent damages must be rejected at startup, plus one truncatable
tail control that must start and report exactly the tail length found by the
model. The rejected set covers framing (CRC, zero length, sequence gap),
header validity (short header, base ahead), envelope digest, and semantic
validity of checkpoint images (row type, version order, unknown relation,
catalog sequence, unique violation).

## Availability finding worth calling out

`checkpoint-corrupt-after-rename` is classified `refused_after_unconfirmed_checkpoint`
because the checkpoint bytes installed by an interrupted replace are damaged
while the journal itself is intact and covers the same rows. The database
refuses to start, so the *data* is recoverable but the *instance* is not
available without operator action. This is the documented behaviour ("checkpoint
invalid → refuse", no silent fallback), and it is a real availability cost of
the atomic-replace design: a torn checkpoint write that happens to complete the
rename loses availability even though the journal suffix is complete. The
matrix records this case separately from data-loss cases; it is not marked
`BROKEN` because the invariant is "never silently accept damaged bytes", not
"always start".

## Not covered / weaker than real life

1. **Power-loss write cache.** The injector stops at syscall boundaries on a
live kernel. Bytes written but not fsynced are still visible to the harness's
`pread` because the page cache retains them. The suite therefore proves
relative ordering (an fsync that returned implies the bytes were handed to the
device) but cannot simulate a volatile write cache that loses fsynced-looking
data. A `kill-after:write` case therefore always sees the frame; on a real
power loss it might not.
2. **Filesystem variability.** All results are from `virtiofs` (the `/workspace`
mount) with overlayfs available. tmpfs and ext4 have different rename/fsync
behaviour. The tracer records per-case timings but no case asserts on them.
3. **Restore into an existing directory** is only observed via the retry probe;
there is no case where a valid restore is layered onto a partially installed
directory or where two restores race.
4. **Concurrent multi-writer durability.** Commits are serialized by the
engine's global lock, so one journal write at a time. The matrix does not test
interleaving of a checkpoint with an in-flight commit beyond the concurrent
backup case.
5. **Vacuum / horizon persistence** interacts with recovery but only appears in
the setup (the `vacuum` record kind is replayed). No case kills inside vacuum
publication, and no case checks that a horizon advanced after the last
checkpoint is durable through an unconfirmed kill.
6. **Unique-index and multi-relation atomicity** are exercised only through a
synthetic index inside a corrupted image (`checkpoint-unique-violation`). No
live case commits across two relations or violates a unique constraint at a
fault boundary.
7. **Index build durability.** `POST /indexes` is a journal record, but no case
targets its write/fsync separately.
8. **Change feed.** `history_base` after restore is asserted implicitly (the
journal header base), but no case kills during a changes request.
9. **Memory/OOM and capacity limits** are not exercised.
10. **`abort-after` is not an exact freeze.** Go's fatal-signal handler needs
other goroutines runnable, so post-boundary work is racy by construction; the
matrix marks these rows `no (racy)`.

## Determinism status

Every non-abort case is a hard stop at a syscall boundary (`SIGSTOP` then
`SIGKILL`) and is expected to reproduce the same classification. `--repeat N`
runs every selected case N times from clean directories and records:
`repeat.consistent`, the per-run classification list, and the per-run 200/not
observation. `selfcheck.py harness-repeatability` independently verifies that
the same boundary produces the same survival pattern five times.

The cases that are **expected** to vary are:

- `commit-abort-after-fsync` (no freeze; racy by construction). In the
  canonical run it produced 2× `unconfirmed_persisted` and 1×
  `confirmed_and_persisted` across three repeats: sometimes the runtime
  finished writing the 200 before the fatal abort took it down. The row is
  durable in every run; only the *response observation* flips. This is
  reported as inconsistent on purpose rather than hidden.
- Under heavy load a client may see a 5xx versus a transport death for the
  same injected error; the classification stays `unconfirmed_*` in both. In
  the canonical run `commit-eio-at-fsync` deterministically recorded 503.

The harness treats a differing classification across repeats as
`INCONSISTENT` in the summary, never silently averaging it away.
