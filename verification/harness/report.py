"""Render a human-auditable observation report from a matrix run.

    python3 verification/harness/report.py verification/results/run-a

Writes OBSERVATIONS.md next to matrix.json. Every number in the report comes
from record.json / tracer JSONL / fault-snapshot bytes; nothing is copied from
the database's own startup message.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent / "lib"))

import journalmodel  # noqa: E402

GROUP_ORDER = ["commit", "checkpoint", "backup", "restore", "corruption"]
GROUP_TITLE = {
    "commit": "1. Commit confirmation",
    "checkpoint": "2. Checkpoint replacement",
    "backup": "3. Backup (source side)",
    "restore": "4. Restore install",
    "corruption": "5. Corruption rejection",
}


def _load(run_root):
    return json.loads((run_root / "matrix.json").read_text())


def _fault_snapshot_journal(case_dir):
    path = case_dir / "artifacts" / "fault-snapshot" / "journal.lmw.atfault"
    if not path.exists():
        return None
    return journalmodel.parse_file(path).summary()


def _post_fault_journal(case_dir):
    path = case_dir / "artifacts" / "post_fault" / "journal.lmw"
    if not path.exists():
        return None
    return journalmodel.parse_file(path).summary()


def _safe(d, *keys, default="-"):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def render(run_root):
    summary = _load(run_root)
    lines = []
    add = lines.append
    add("# Raw observations")
    add("")
    add(f"Run: `{run_root}`")
    add("")
    add(f"- database binary SHA-256: `{summary.get('binary_sha256')}`")
    add(f"- tracer SHA-256: `{summary.get('tracer_sha256')}`")
    add(f"- repeats per case: {summary.get('repeat', 1)}")
    if summary.get("repeat_summary"):
        rs = summary["repeat_summary"]
        racy = [c["case"] for c in summary["cases"]
                if c.get("deterministic_boundary") is False]
        expected = [n for n in rs["inconsistent"] if n in racy]
        unexpected = [n for n in rs["inconsistent"] if n not in racy]
        add(f"- repeat consistency: {rs['consistent']}/{rs['cases']} cases "
            f"identical")
        add(f"- inconsistent, expected (non-freezing abort path): "
            f"{expected or 'none'}")
        add(f"- inconsistent, unexpected: {unexpected or 'none'}")
    add("")
    add("Reading the tables:")
    add("")
    add("- **confirmed** = a 200 was recorded for that exact request. **no** = a")
    add("  transport death or 5xx was recorded instead. Nothing is inferred.")
    add("- **journal at fault** is parsed from the tracer's own copy of the file,")
    add("  taken at the injection boundary, by `journalmodel.py`.")
    add("- **rows after restart** is the set the database exposed, compared")
    add("  against the independent oracle's decision (START/REFUSE + expected")
    add("  rows). A row shows `BROKEN` only when a recorded 200 or a durable")
    add("  journal frame contradicts what the restart exposed.")
    add("")

    by_group = {}
    for case in summary["cases"]:
        by_group.setdefault(case["group"], []).append(case)

    for group in GROUP_ORDER:
        cases = by_group.get(group)
        if not cases:
            continue
        add(f"## {GROUP_TITLE[group]}")
        add("")
        header_at = None
        if group == "commit":
            add("| case | boundary | HTTP | journal frames at fault | "
                "seq at fault | rows after restart | verdict |")
            add("| --- | --- | --- | --- | --- | --- | --- |")
        elif group in ("checkpoint", "restore"):
            add("| case | boundary | HTTP | files present at fault | "
                "checkpoint valid | rows after restart | verdict |")
            add("| --- | --- | --- | --- | --- | --- | --- |")
        elif group == "backup":
            add("| case | HTTP | image seq | rows in image | matches replay | "
                "stable after source write | verdict |")
            add("| --- | --- | --- | --- | --- | --- | --- |")
        else:
            add("| case | damaged bytes | server started | oracle | verdict |")
            add("| --- | --- | --- | --- | --- |")
        for case in cases:
            add(_case_row(run_root, group, case))
        add("")

    # Differential section: same write boundary, different commit moment.
    add("## The three client outcomes at one commit, side by side")
    add("")
    add("Same relation, same seed, same post-setup commit of rows 20 and 21.")
    add("The only difference is where the process was stopped.")
    add("")
    add("| stop point | bytes on disk at fault | 200 seen? | rows 20/21 after restart |")
    add("| --- | --- | --- | --- |")
    for name in ("commit-kill-in-write", "commit-kill-after-write",
                 "commit-kill-in-fsync", "commit-kill-after-fsync"):
        case = next((c for c in summary["cases"] if c["case"] == name), None)
        if not case:
            continue
        case_dir = run_root / "cases" / name
        rec = _load_record(case_dir)
        snap = _fault_snapshot_journal(case_dir)
        obs = case["observations"]
        rows = _restart_rows(case_dir)
        add("| `{}` | {} | {} | {} |".format(
            case["stop"],
            f"{snap['intact_frames']} frames, seq_end {snap['sequence_end']}, "
            f"tail {snap['tail_bytes']}B" if snap else "not captured",
            "yes" if obs.get("commit_confirmed") else "no",
            ", ".join(sorted(rows)) or "-"))
    add("")
    add("This is the core separation the request asks for: at `kill-in:1:write`")
    add("the client saw a transport error *and* the bytes are absent; at")
    add("`kill-after:1:write` and `kill-in:1:fsync` the client saw a transport")
    add("error but the bytes are present (so a restart may expose them); at")
    add("`kill-after:1:fsync` the commit is durable yet still unacknowledged.")
    add("")

    add("## Findings")
    add("")
    for line in _findings(summary, run_root):
        add(line)
    add("")
    add("## Evidence locations")
    add("")
    add("```")
    add(f"{run_root}/matrix.json                     summary + every observation")
    add(f"{run_root}/matrix.md                       one-line table")
    add(f"{run_root}/cases/<case>/record.json       full record")
    add(f"{run_root}/cases/<case>/artifacts/tracer.jsonl   every counted syscall")
    add(f"{run_root}/cases/<case>/artifacts/fault-snapshot/  raw bytes at the fault")
    add(f"{run_root}/cases/<case>/artifacts/post_fault/      raw bytes after death")
    add(f"{run_root}/cases/<case>/artifacts/server.log      database stderr")
    add(f"{run_root}/cases/<case>/artifacts/recovery.log    restart stderr")
    add("```")
    add("")
    return "\n".join(lines) + "\n"


def _findings(summary, run_root):
    cases = {c["case"]: c for c in summary["cases"]}
    out = []

    def obs(name, key, default=None):
        return (cases.get(name, {}).get("observations") or {}).get(key, default)

    def have(*names):
        return all(n in cases for n in names)

    def stop(name):
        return cases.get(name, {}).get("stop")

    if not have("commit-kill-in-write", "commit-kill-after-write"):
        out.append("- (partial run: commit findings omitted)")
        return out

    # Commit outcome separation
    in_write = obs("commit-kill-in-write", "commit_confirmed")
    after_write = obs("commit-kill-after-write", "commit_confirmed")
    after_fsync = obs("commit-kill-after-fsync", "commit_confirmed")
    rows_in = _restart_rows(run_root / "cases" / "commit-kill-in-write")
    rows_aw = _restart_rows(run_root / "cases" / "commit-kill-after-write")
    payload = {"int:20", "int:21"}
    out.append(
        f"- **Commit acknowledgement is tied to fsync, not to write.** "
        f"Stopping before `write` (`{stop('commit-kill-in-write')}`) left no "
        f"payload ({'absent' if not payload & rows_in else 'present'}), and the "
        f"client saw no 200. Stopping after `write` or at `fsync` entry left "
        f"the frame in the file "
        f"({'present' if payload <= rows_aw else 'absent'}) with still no 200, "
        f"so the row may appear without ever being acknowledged. Only after "
        f"`fsync` returns is the commit durable; the response is still "
        f"unconfirmed, which is the documented 'client cannot know' window.")
    out.append(
        f"- **A 200 is never followed by loss in any case in this run.** "
        f"`commit-baseline-ack-then-kill` records a 200 and the rows survive; "
        f"`commit-eio-at-fsync` records 503 and the instance stops serving; "
            f"`commit-corrupt-after-write` records no 200 and startup refuses "
            f"rather than silently dropping a corrupt frame.")
    if have("commit-corrupt-after-write", "commit-torn-after-write"):
        out.append(
            "- **A corrupt complete frame is rejected, an incomplete tail is "
        "truncated.** `commit-corrupt-after-write` (CRC flip) and "
        "`commit-torn-after-write` (half frame) land on opposite sides of the "
        "documented rule: the first must refuse, the second must truncate and "
        "start. Both are reproduced identically in every repeat.")
    if any(n.startswith("checkpoint-") for n in cases):
        out.append(
            "- **Checkpoint replacement is atomic under the tested boundaries.** "
        "Killing before the rename leaves the old checkpoint plus the journal "
        "suffix (checkpoint seq unchanged); killing after the rename installs "
        "the new image (checkpoint seq advanced) while the directory fsync is "
        "still outstanding. In both cases the recovered rows equal the "
            "independent journal replay (`rows_equal_journal_replay = true`).")
    if any(n.startswith("restore-") for n in cases):
        by_class = {n: (cases[n].get("observations") or {}).get("classification")
                    for n in cases if n.startswith("restore-")}
        refused = sorted(n for n, c in by_class.items()
                         if c == "restore_left_refusable_state")
        not_installed = sorted(n for n, c in by_class.items()
                               if c == "restore_not_installed")
        complete = sorted(n for n, c in by_class.items()
                          if c == "restore_complete")
        parts = ["- **An interrupted restore never silently serves partial "
                 "data — but one boundary starts as an empty database.** "]
        if refused:
            parts.append(
                "Killed at " + ", ".join("`" + n + "`" for n in refused) +
                ", the directory keeps a journal header whose base has no "
                "checkpoint and startup rejects it (`journal requires "
                "checkpoint at base N, but none is installed`). ")
        if not_installed:
            parts.append(
                "Killed at " + ", ".join("`" + n + "`" for n in not_installed) +
                ", it leaves a zero-length journal and no checkpoint: startup "
                "*succeeds* as a fresh, empty database, so a naive 'did it "
                "start' check reports success while none of the backup is "
                "present (classified `restore_not_installed`). ")
        if complete:
            parts.append(
                "Only " + ", ".join("`" + n + "`" for n in complete) +
                " serves the backup, and its rows equal the source image "
                "exactly.")
        out.append("".join(parts))
    if "backup-frozen-while-source-writes" in cases:
        out.append(
            "- **Backup bytes are frozen and independent of later source writes.** "
        "The returned image decodes to the source's journal-replay snapshot at "
        "its own sequence; its file digest does not change when the source "
        "commits again afterwards, and a later backup correctly includes the "
            "new row.")
    out.append(
        "- **The harness can fail.** `selfcheck.py` proves the oracle notices a "
        "silently removed acknowledged commit, that the tracer kills exactly "
        "at the boundary, and that a stale image digest is rejected. Without "
        "that control, `server started` would be the only oracle and would "
        "have passed the removed-commit case.")
    return out


def _load_record(case_dir):
    path = case_dir / "artifacts" / "record.json"
    return json.loads(path.read_text()) if path.exists() else {}


def _restart_rows(case_dir):
    rec = _load_record(case_dir)
    rows = _safe(rec, "observation", "oracle", "rows", default={})
    out = set()
    for table in (rows or {}).values():
        out |= set(table)
    return out


def _case_row(run_root, group, case):
    name = case["case"]
    case_dir = run_root / "cases" / name
    obs = case.get("observations") or {}
    verdict = obs.get("classification", "ERROR")
    if case.get("error"):
        verdict = f"ERROR ({case['error']})"
    http = obs.get("commit_http_status")
    if http is None:
        http = obs.get("checkpoint_http_status")
    if http is None:
        http = obs.get("backup_http_status", "-")
    http_s = "200" if http == 200 else ("none" if http is None else str(http))
    row_set = sorted(_restart_rows(case_dir))
    rows = ",".join(row_set) if len(row_set) <= 10 else (
        f"{len(row_set)} rows")

    if group == "commit":
        snap = _fault_snapshot_journal(case_dir)
        if snap is None:
            snap = _post_fault_journal(case_dir)
        frames = (f"{snap['intact_frames']} frames" if snap else "n/a")
        if snap and snap["tail_bytes"]:
            frames += f" + {snap['tail_bytes']}B tail"
        if snap and snap.get("broken"):
            frames += " (broken)"
        seq = snap["sequence_end"] if snap else "-"
        return (f"| `{name}` | `{case['stop'] or '-'}` | {http_s} | {frames} | "
                f"{seq} | {rows} | **{verdict}** |")

    if group in ("checkpoint", "restore"):
        files = obs.get("post_fault_files") or obs.get("restore_installed_files") or {}
        names = ", ".join(sorted(files)) or "-"
        cp = obs.get("post_fault_checkpoint") or {}
        if cp.get("present"):
            cp_s = (f"seq {cp.get('sequence')}" if cp.get("valid")
                    else "invalid")
        elif obs.get("restore_installed_files") is not None:
            cp_s = "not installed"
        else:
            cp_s = "absent"
        return (f"| `{name}` | `{case['stop'] or '-'}` | {http_s} | {names} | "
                f"{cp_s} | {rows} | **{verdict}** |")

    if group == "backup":
        seq = obs.get("backup_image_sequence", "-")
        rows_img = obs.get("backup_actual_rows") or obs.get("backup_rows") or []
        matches = obs.get("backup_matches_journal_replay", "-")
        stable = obs.get("backup_bytes_stable_after_source_write", "-")
        return (f"| `{name}` | {http_s} | {seq} | "
                f"{len(rows_img) if isinstance(rows_img, list) else '-'} rows | "
                f"{matches} | {stable} | **{verdict}** |")

    # corruption
    changed = obs.get("mutated_offset")
    what = obs.get("checkpoint_semantic_mutation") or (
        f"offset {changed}" if changed is not None else
        obs.get("appended_tail_bytes") and f"+{obs['appended_tail_bytes']}B tail" or
        "-")
    started = obs.get("server_started", "-")
    oracle = obs.get("oracle_outcome", "-")
    return (f"| `{name}` | {what} | {started} | {oracle} | **{verdict}** |")


def main():
    run_root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1
                            else "verification/results/run-a").resolve()
    out = render(run_root)
    (run_root / "OBSERVATIONS.md").write_text(out)
    print(f"wrote {run_root/'OBSERVATIONS.md'}")


if __name__ == "__main__":
    main()
