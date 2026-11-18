# Raw observations

Run: `/workspace/verification/results/run-final`

- database binary SHA-256: `f97c55a62590ef856cc5cb1ef9e09f58d62fb87b897b70745cc8ff0ca8f61e1d`
- tracer SHA-256: `d4e101622354eec13b95c62a0a653e801f4bea9dc4a8f60159df4393453bb954`
- repeats per case: 3
- repeat consistency: 37/38 cases identical
- inconsistent, expected (non-freezing abort path): ['commit-abort-after-fsync']
- inconsistent, unexpected: none

Reading the tables:

- **confirmed** = a 200 was recorded for that exact request. **no** = a
  transport death or 5xx was recorded instead. Nothing is inferred.
- **journal at fault** is parsed from the tracer's own copy of the file,
  taken at the injection boundary, by `journalmodel.py`.
- **rows after restart** is the set the database exposed, compared
  against the independent oracle's decision (START/REFUSE + expected
  rows). A row shows `BROKEN` only when a recorded 200 or a durable
  journal frame contradicts what the restart exposed.

## 1. Commit confirmation

| case | boundary | HTTP | journal frames at fault | seq at fault | rows after restart | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `commit-baseline-ack-then-kill` | `-` | 200 | 4 frames | 4 | int:1,int:2,int:20,int:21,int:3,int:4,int:5 | **confirmed_and_persisted** |
| `commit-kill-in-write` | `kill-in:1:write` | - | 3 frames | 3 | int:1,int:2,int:3,int:4,int:5 | **unconfirmed_absent** |
| `commit-kill-after-write` | `kill-after:1:write` | - | 4 frames | 4 | int:1,int:2,int:20,int:21,int:3,int:4,int:5 | **unconfirmed_persisted** |
| `commit-kill-in-fsync` | `kill-in:1:fsync` | - | 4 frames | 4 | int:1,int:2,int:20,int:21,int:3,int:4,int:5 | **unconfirmed_persisted** |
| `commit-kill-after-fsync` | `kill-after:1:fsync` | - | 4 frames | 4 | int:1,int:2,int:20,int:21,int:3,int:4,int:5 | **unconfirmed_persisted** |
| `commit-abort-after-fsync` | `abort-after:1:fsync` | 200 | 4 frames | 4 | int:1,int:2,int:20,int:21,int:3,int:4,int:5 | **confirmed_and_persisted** |
| `commit-eio-at-fsync` | `eio-after:1:fsync` | 503 | 4 frames | 4 | int:1,int:2,int:20,int:21,int:3,int:4,int:5 | **unconfirmed_persisted** |
| `commit-corrupt-after-write` | `kill-after:1:write` | - | 3 frames + 309B tail (broken) | 3 |  | **must_refuse** |
| `commit-torn-after-write` | `torn-after:1:write` | - | 3 frames + 162B tail | 3 | int:1,int:2,int:3,int:4,int:5 | **unconfirmed_absent** |
| `commit-multi-frame-after-write` | `kill-after:1:write` | - | 4 frames | 4 | 45 rows | **unconfirmed_persisted** |

## 2. Checkpoint replacement

| case | boundary | HTTP | files present at fault | checkpoint valid | rows after restart | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `checkpoint-baseline-ack-then-kill` | `-` | 200 | checkpoint.lmi, journal.lmw, lamina.lock | seq 3 | int:1,int:2,int:3,int:4,int:5 | **confirmed_and_recovered** |
| `checkpoint-kill-after-temp-fsync` | `kill-after:1:fsync` | - | .lamina-image-898754966, checkpoint.lmi, journal.lmw, lamina.lock | seq 2 | int:1,int:10,int:11,int:2,int:3,int:4,int:5 | **recovered** |
| `checkpoint-kill-in-rename` | `kill-in:1:rename` | - | .lamina-image-301040758, checkpoint.lmi, journal.lmw, lamina.lock | seq 2 | int:1,int:10,int:11,int:2,int:3,int:4,int:5 | **recovered** |
| `checkpoint-kill-after-rename` | `kill-after:1:rename` | - | checkpoint.lmi, journal.lmw, lamina.lock | seq 4 | int:1,int:10,int:11,int:2,int:3,int:4,int:5 | **recovered** |
| `checkpoint-kill-after-dir-fsync` | `kill-after:2:fsync` | - | checkpoint.lmi, journal.lmw, lamina.lock | seq 4 | int:1,int:10,int:11,int:2,int:3,int:4,int:5 | **recovered** |
| `checkpoint-corrupt-after-rename` | `kill-after:1:rename` | - | checkpoint.lmi, journal.lmw, lamina.lock | invalid |  | **refused_after_unconfirmed_checkpoint** |
| `checkpoint-kill-after-unlink-temp` | `kill-after:1:unlink` | - | checkpoint.lmi, journal.lmw, lamina.lock | seq 4 | int:1,int:10,int:11,int:2,int:3,int:4,int:5 | **recovered** |
| `checkpoint-twice-kill-in-second-rename` | `kill-in:2:rename` | 200 | .lamina-image-399936309, checkpoint.lmi, journal.lmw, lamina.lock | seq 4 | int:1,int:10,int:11,int:2,int:3,int:4,int:5 | **recovered** |

## 3. Backup (source side)

| case | HTTP | image seq | rows in image | matches replay | stable after source write | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `backup-frozen-while-source-writes` | 200 | 4 | 7 rows | True | True | **backup_frozen_and_source_recoverable** |

## 4. Restore install

| case | boundary | HTTP | files present at fault | checkpoint valid | rows after restart | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `restore-kill-in-journal-header-write` | `kill-in:1:write` | - | journal.lmw, lamina.lock | not installed |  | **restore_not_installed** |
| `restore-kill-after-journal-header-fsync` | `kill-after:1:fsync` | - | journal.lmw, lamina.lock | not installed |  | **restore_left_refusable_state** |
| `restore-kill-in-image-write` | `kill-in:2:write` | - | .lamina-image-3365834357, journal.lmw, lamina.lock | not installed |  | **restore_left_refusable_state** |
| `restore-kill-after-image-fsync` | `kill-after:3:fsync` | - | .lamina-image-1974771100, journal.lmw, lamina.lock | not installed |  | **restore_left_refusable_state** |
| `restore-kill-after-rename` | `kill-after:1:rename` | - | checkpoint.lmi, journal.lmw, lamina.lock | not installed | int:1,int:2,int:3 | **restore_complete** |
| `restore-corrupt-before-install` | `kill-after:1:rename` | - | checkpoint.lmi, journal.lmw, lamina.lock | not installed |  | **restore_left_refusable_state** |
| `restore-tampered-digest` | `-` | - | - | not installed |  | **restore_aborted_cleanly** |

## 5. Corruption rejection

| case | damaged bytes | server started | oracle | verdict |
| --- | --- | --- | --- | --- |
| `corrupt-journal-crc-flip` | offset 884 | False | refuse | **refused_as_required** |
| `corrupt-journal-length-zero` | offset 730 | False | refuse | **refused_as_required** |
| `corrupt-journal-sequence-gap` | offset 730 | False | refuse | **refused_as_required** |
| `corrupt-journal-header-truncated` | - | False | refuse | **refused_as_required** |
| `corrupt-journal-base-ahead` | - | False | refuse | **refused_as_required** |
| `corrupt-checkpoint-digest-mismatch` | offset 121 | False | refuse | **refused_as_required** |
| `corrupt-checkpoint-row-type` | row primary type changed to text | False | refuse | **refused_as_required** |
| `corrupt-checkpoint-version-order` | version sequence 0 (invalid order) | False | refuse | **refused_as_required** |
| `corrupt-checkpoint-unknown-relation` | store references unknown relation | False | refuse | **refused_as_required** |
| `corrupt-checkpoint-catalog-sequence` | relation created sequence 0 | False | refuse | **refused_as_required** |
| `corrupt-checkpoint-unique-violation` | two current rows share a unique value | False | refuse | **refused_as_required** |
| `corrupt-journal-tail-garbage` | +3B tail | True | start | **accepted_cleanly** |

## The three client outcomes at one commit, side by side

Same relation, same seed, same post-setup commit of rows 20 and 21.
The only difference is where the process was stopped.

| stop point | bytes on disk at fault | 200 seen? | rows 20/21 after restart |
| --- | --- | --- | --- |
| `kill-in:1:write` | 3 frames, seq_end 3, tail 0B | no | int:1, int:2, int:3, int:4, int:5 |
| `kill-after:1:write` | 4 frames, seq_end 4, tail 0B | no | int:1, int:2, int:20, int:21, int:3, int:4, int:5 |
| `kill-in:1:fsync` | 4 frames, seq_end 4, tail 0B | no | int:1, int:2, int:20, int:21, int:3, int:4, int:5 |
| `kill-after:1:fsync` | 4 frames, seq_end 4, tail 0B | no | int:1, int:2, int:20, int:21, int:3, int:4, int:5 |

This is the core separation the request asks for: at `kill-in:1:write`
the client saw a transport error *and* the bytes are absent; at
`kill-after:1:write` and `kill-in:1:fsync` the client saw a transport
error but the bytes are present (so a restart may expose them); at
`kill-after:1:fsync` the commit is durable yet still unacknowledged.

## Findings

- **Commit acknowledgement is tied to fsync, not to write.** Stopping before `write` (`kill-in:1:write`) left no payload (absent), and the client saw no 200. Stopping after `write` or at `fsync` entry left the frame in the file (present) with still no 200, so the row may appear without ever being acknowledged. Only after `fsync` returns is the commit durable; the response is still unconfirmed, which is the documented 'client cannot know' window.
- **A 200 is never followed by loss in any case in this run.** `commit-baseline-ack-then-kill` records a 200 and the rows survive; `commit-eio-at-fsync` records 503 and the instance stops serving; `commit-corrupt-after-write` records no 200 and startup refuses rather than silently dropping a corrupt frame.
- **A corrupt complete frame is rejected, an incomplete tail is truncated.** `commit-corrupt-after-write` (CRC flip) and `commit-torn-after-write` (half frame) land on opposite sides of the documented rule: the first must refuse, the second must truncate and start. Both are reproduced identically in every repeat.
- **Checkpoint replacement is atomic under the tested boundaries.** Killing before the rename leaves the old checkpoint plus the journal suffix (checkpoint seq unchanged); killing after the rename installs the new image (checkpoint seq advanced) while the directory fsync is still outstanding. In both cases the recovered rows equal the independent journal replay (`rows_equal_journal_replay = true`).
- **An interrupted restore never silently serves partial data — but one boundary starts as an empty database.** Killed at `restore-corrupt-before-install`, `restore-kill-after-image-fsync`, `restore-kill-after-journal-header-fsync`, `restore-kill-in-image-write`, the directory keeps a journal header whose base has no checkpoint and startup rejects it (`journal requires checkpoint at base N, but none is installed`). Killed at `restore-kill-in-journal-header-write`, it leaves a zero-length journal and no checkpoint: startup *succeeds* as a fresh, empty database, so a naive 'did it start' check reports success while none of the backup is present (classified `restore_not_installed`). Only `restore-kill-after-rename` serves the backup, and its rows equal the source image exactly.
- **Backup bytes are frozen and independent of later source writes.** The returned image decodes to the source's journal-replay snapshot at its own sequence; its file digest does not change when the source commits again afterwards, and a later backup correctly includes the new row.
- **The harness can fail.** `selfcheck.py` proves the oracle notices a silently removed acknowledged commit, that the tracer kills exactly at the boundary, and that a stale image digest is rejected. Without that control, `server started` would be the only oracle and would have passed the removed-commit case.

## Evidence locations

```
/workspace/verification/results/run-final/matrix.json                     summary + every observation
/workspace/verification/results/run-final/matrix.md                       one-line table
/workspace/verification/results/run-final/cases/<case>/record.json       full record
/workspace/verification/results/run-final/cases/<case>/artifacts/tracer.jsonl   every counted syscall
/workspace/verification/results/run-final/cases/<case>/artifacts/fault-snapshot/  raw bytes at the fault
/workspace/verification/results/run-final/cases/<case>/artifacts/post_fault/      raw bytes after death
/workspace/verification/results/run-final/cases/<case>/artifacts/server.log      database stderr
/workspace/verification/results/run-final/cases/<case>/artifacts/recovery.log    restart stderr
```

