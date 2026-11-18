"""The durability fault matrix: case list and command-line entry point.

Usage:
    python3 verification/harness/matrix.py --list
    python3 verification/harness/matrix.py --group commit
    python3 verification/harness/matrix.py --case commit-kill-after-fsync
    python3 verification/harness/matrix.py            # all cases

Each case writes verification/results/<run>/<case>/record.json and a summary
row into verification/results/<run>/matrix.json + matrix.md.
"""
import argparse
import datetime
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve()
PROJECT = HERE.parents[2]
sys.path.insert(0, str(HERE.parent / "lib"))

import corruptions  # noqa: E402
import runner  # noqa: E402
import scenarios as S  # noqa: E402


def build_cases(run_root, binary, tracer):
    cases = []

    def add(spec, name=None):
        spec._case_name = name or spec.name
        spec._run_root = run_root
        cases.append(spec)

    # ---- COMMIT CONFIRMATION ------------------------------------------------
    # The commit frame is one write(2)+fsync(2) pair on journal.lmw. Numbering
    # starts at the first counted journal write after arming.
    add(S.CommitScenario(
        _ctx(run_root, "commit-baseline-ack-then-kill"),
        [S.row(20), S.row(21)], stop=None,
        description="Control: commit acknowledged with 200, then unannounced "
                    "SIGKILL with no pending durability work."), "commit-baseline-ack-then-kill")
    cases[-1] = _ack_case(run_root)
    cases[-1]._case_name = "commit-baseline-ack-then-kill"
    cases[-1]._run_root = run_root
    add(S.CommitScenario(
        _ctx(run_root, "commit-kill-in-write"),
        [S.row(20), S.row(21)], stop="kill-in:1:write",
        description="SIGKILL at write(2) entry: frame bytes never entered the "
                    "kernel. Client sees a transport error."), "commit-kill-in-write")
    add(S.CommitScenario(
        _ctx(run_root, "commit-kill-after-write"),
        [S.row(20), S.row(21)], stop="kill-after:1:write",
        description="SIGKILL after write(2) returned, before fsync(2): frame "
                    "is in the page cache only."), "commit-kill-after-write")
    add(S.CommitScenario(
        _ctx(run_root, "commit-kill-in-fsync"),
        [S.row(20), S.row(21)], stop="kill-in:1:fsync",
        description="SIGKILL at fsync(2) entry: full frame written, durability "
                    "barrier not entered."), "commit-kill-in-fsync")
    add(S.CommitScenario(
        _ctx(run_root, "commit-kill-after-fsync"),
        [S.row(20), S.row(21)], stop="kill-after:1:fsync",
        description="SIGKILL after fsync(2) completed but before the 200 was "
                    "written: durable, unacknowledged."), "commit-kill-after-fsync")
    add(S.CommitScenario(
        _ctx(run_root, "commit-abort-after-fsync"),
        [S.row(20), S.row(21)], stop="abort-after:1:fsync",
        description="SIGABRT via the Go runtime fatal path after fsync(2); "
                    "exercises crash-during-response."), "commit-abort-after-fsync")
    add(S.CommitScenario(
        _ctx(run_root, "commit-eio-at-fsync"),
        [S.row(20), S.row(21)], stop="eio-after:1:fsync",
        description="fsync(2) returns EIO after the syscall: the instance must "
                    "stop serving (503) and must not acknowledge the commit."), "commit-eio-at-fsync")
    add(S.CommitScenario(
        _ctx(run_root, "commit-corrupt-after-write"),
        [S.row(20), S.row(21)], stop="kill-after:1:write",
        corrupt_flip=True,
        description="Flip a payload byte of the frame that write(2) just "
                    "persisted, then SIGKILL. Must be refused at startup."), "commit-corrupt-after-write")
    add(S.CommitScenario(
        _ctx(run_root, "commit-torn-after-write"),
        [S.row(20), S.row(21)], stop="torn-after:1:write",
        description="Media failure shortens the frame that write(2) returned: "
                    "the file ends mid-frame. Must be truncated as an "
                    "incomplete tail, never half-applied."),
        "commit-torn-after-write")
    add(S.CommitScenario(
        _ctx(run_root, "commit-multi-frame-after-write"),
        [S.row(20 + i) for i in range(40)], stop="kill-after:1:write",
        description="Large multi-row commit: one frame, abruptly ended after "
                    "write(2). Tests atomicity of an unconfirmed large write."), "commit-multi-frame-after-write")

    # ---- CHECKPOINT REPLACEMENT --------------------------------------------
    add(S.AckThenKillCheckpoint(
        _ctx(run_root, "checkpoint-baseline-ack-then-kill")),
        "checkpoint-baseline-ack-then-kill")
    # watch covers <dir>/* so fsync(temp) is #1 and fsync(dir) is #2; rename
    # is #1. kill-in:1:rename freezes before the replacement takes effect.
    add(S.CheckpointScenario(
        _ctx(run_root, "checkpoint-kill-after-temp-fsync"),
        stop="kill-after:1:fsync",
        description="Kill after the temp image is fsynced but before rename: "
                    "old checkpoint must remain authoritative."), "checkpoint-kill-after-temp-fsync")
    add(S.CheckpointScenario(
        _ctx(run_root, "checkpoint-kill-in-rename"),
        stop="kill-in:1:rename",
        description="Kill at rename(2) entry: temp image complete, atomic "
                    "replacement not executed."), "checkpoint-kill-in-rename")
    add(S.CheckpointScenario(
        _ctx(run_root, "checkpoint-kill-after-rename"),
        stop="kill-after:1:rename",
        description="Kill after rename(2): checkpoint name points at new image, "
                    "directory fsync not yet done."), "checkpoint-kill-after-rename")
    add(S.CheckpointScenario(
        _ctx(run_root, "checkpoint-kill-after-dir-fsync"),
        stop="kill-after:2:fsync",
        description="Kill after the directory fsync: replacement fully durable "
                    "but the response was not sent."), "checkpoint-kill-after-dir-fsync")
    add(S.CheckpointScenario(
        _ctx(run_root, "checkpoint-corrupt-after-rename"),
        stop="kill-after:1:rename", corrupt_flip=True,
        description="Byte-flip inside the freshly renamed checkpoint before the "
                    "directory sync. Startup must refuse rather than fall back "
                    "silently to the journal."), "checkpoint-corrupt-after-rename")
    add(S.CheckpointScenario(
        _ctx(run_root, "checkpoint-kill-after-unlink-temp"),
        stop="kill-after:1:unlink",
        description="Kill after the temp file is unlinked: only the renamed "
                    "checkpoint survives."), "checkpoint-kill-after-unlink-temp")
    add(S.CheckpointScenario(
        _ctx(run_root, "checkpoint-twice-kill-in-second-rename"),
        stop="kill-in:2:rename", repeat=2,
        description="Two checkpoints in a row, killed at the second rename: "
                    "the first replacement must remain intact."), "checkpoint-twice-kill-in-second-rename")

    # ---- BACKUP (source side) ----------------------------------------------
    add(S.BackupScenario(
        _ctx(run_root, "backup-frozen-while-source-writes"),
        description="Backup taken while a concurrent commit lands; the returned "
                    "image must match journal replay at its own sequence.",
        during_rows=[S.row(30), S.row(31)]), "backup-frozen-while-source-writes")

    # ---- RESTORE INSTALL ---------------------------------------------------
    # Restore order: journal header write+fsync, temp image write, temp image
    # fsync, rename checkpoint, then startup open.
    add(S.RestoreScenario(
        _ctx(run_root, "restore-kill-in-journal-header-write"),
        stop="kill-in:1:write",
        description="Kill at the restore's journal-header write: no complete "
                    "install; the new directory must not serve partial data."), "restore-kill-in-journal-header-write")
    add(S.RestoreScenario(
        _ctx(run_root, "restore-kill-after-journal-header-fsync"),
        stop="kill-after:1:fsync",
        description="Kill after the restore journal header is durable but "
                    "before the image is written."), "restore-kill-after-journal-header-fsync")
    add(S.RestoreScenario(
        _ctx(run_root, "restore-kill-in-image-write"),
        stop="kill-in:2:write",
        description="Kill at the image temp-file write: header exists, no "
                    "checkpoint bytes."), "restore-kill-in-image-write")
    add(S.RestoreScenario(
        _ctx(run_root, "restore-kill-after-image-fsync"),
        stop="kill-after:3:fsync",
        description="Kill after the temp image is durable but before rename. "
                    "(fsync #1 is the journal header, #2 the directory after "
                    "header creation, #3 the temp image.)"), "restore-kill-after-image-fsync")
    add(S.RestoreScenario(
        _ctx(run_root, "restore-kill-after-rename"),
        stop="kill-after:1:rename",
        description="Kill after the restore rename: checkpoint installed, "
                    "startup has not validated it."), "restore-kill-after-rename")
    add(S.RestoreScenario(
        _ctx(run_root, "restore-corrupt-before-install"),
        stop="kill-after:1:rename", corrupt_flip=True,
        description="Byte-flip in the installed image at rename time: restore "
                    "must not leave a directory that silently serves damaged "
                    "data."), "restore-corrupt-before-install")
    add(S.RestoreScenario(
        _ctx(run_root, "restore-tampered-digest"),
        stop=None,
        tamper=lambda path, ctx: _tamper_digest(path, ctx),
        description="Backup envelope digest does not match payload: restore "
                    "must refuse and leave no directory."), "restore-tampered-digest")

    # ---- CORRUPTION REJECTION ---------------------------------------------
    for label, fn, desc in [
        ("journal-crc-flip", corruptions.journal_crc_flip,
         "Complete frame with a bad CRC (bit rot mid-file)."),
        ("journal-length-zero", corruptions.journal_length_zero,
         "Frame length field set to 0 (illegal framing)."),
        ("journal-sequence-gap", corruptions.journal_sequence_gap,
         "Internally valid frame with sequence discontinuity."),
        ("journal-header-truncated", corruptions.journal_header_truncated,
         "Header shorter than 16 bytes."),
        ("journal-base-ahead", corruptions.journal_header_base_ahead,
         "Journal header requires a newer checkpoint than exists."),
        ("checkpoint-digest-mismatch", corruptions.checkpoint_digest_mismatch,
         "Checkpoint payload changed, recorded digest stale."),
        ("checkpoint-row-type", corruptions.checkpoint_row_type,
         "Valid digest, primary value has the wrong type."),
        ("checkpoint-version-order", corruptions.checkpoint_version_order,
         "Valid digest, version sequence is out of order."),
        ("checkpoint-unknown-relation", corruptions.checkpoint_unknown_relation,
         "Valid digest, store references a relation absent from catalog."),
        ("checkpoint-catalog-sequence", corruptions.checkpoint_catalog_sequence,
         "Valid digest, relation created at sequence 0."),
        ("checkpoint-unique-violation", corruptions.checkpoint_unique_violation,
         "Valid digest, current rows violate a unique index."),
    ]:
        add(S.CorruptScenario(_ctx(run_root, "corrupt-" + label), fn,
                              description=desc, label=label),
            "corrupt-" + label)
    # Non-refusal control: an incomplete tail is explicitly truncatable.
    add(S.CorruptScenario(
        _ctx(run_root, "corrupt-journal-tail-garbage"),
                          corruptions.journal_tail_garbage,
                          description="3-byte incomplete tail: documented as "
                                      "truncatable, must start and expose the "
                                      "intact prefix.",
                          label="journal-tail-garbage"), "corrupt-journal-tail-garbage")
    return cases


_CASE_CTX = {}


def _ctx(run_root, name):
    return {"run_root": run_root, "name": name}


def _ack_case(run_root):
    ctx_holder = {"value": None}

    class _Ctx:
        def __init__(self):
            self.holder = ctx_holder

        def __getattr__(self, item):
            return getattr(self.holder["value"], item)

    spec = S.AckThenKillScenario(_Ctx())
    spec._ctx_holder = ctx_holder
    return spec


def _tamper_digest(path, ctx):
    import json as _json
    data = bytearray(path.read_bytes())
    env = _json.loads(bytes(data))
    env["sha256"] = "0" * 64
    path.write_bytes(_json.dumps(env).encode())
    ctx.record("tamper", "digest replaced with zeros")


def _rebuild(spec, cases, name):
    """Recreate a case object for a repeat run.

    build_cases() is cheap and deterministic; rebuild the full list and pick the
    matching descriptor instead of deep-copying a Context-bound object.
    """
    rebuilt_root = getattr(spec, "_run_root", pathlib.Path("."))
    for candidate in build_cases(rebuilt_root, _BINARY, _TRACER):
        if candidate._case_name == name:
            return candidate
    raise KeyError(name)


def materialize(spec, run_root):
    """Attach a real Context to a case descriptor and pin its case name."""
    name = getattr(spec, "_case_name", None) or spec.name
    spec.name = name
    ctx = runner.Context(_BINARY, _TRACER, run_root, name)
    if hasattr(spec, "_ctx_holder"):
        spec._ctx_holder["value"] = ctx
    spec.ctx = ctx
    return spec


_BINARY = None
_TRACER = None


def main(argv=None):
    global _BINARY, _TRACER
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", default=str(PROJECT / "bin" / "laminad"))
    ap.add_argument("--tracer", default=str(HERE.parent.parent / "tracer" / "laminad-fault"))
    ap.add_argument("--run-root", default=None,
                    help="evidence directory (default verification/results/<ts>)")
    ap.add_argument("--group", choices=sorted(runner.GROUP_STATUS),
                    help="run one persistence path")
    ap.add_argument("--case", action="append", default=[],
                    help="run specific case name(s)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--repeat", type=int, default=1,
                    help="run each case N times and report consistency")
    args = ap.parse_args(argv)
    _BINARY = args.binary
    _TRACER = args.tracer

    run_root = (pathlib.Path(args.run_root).resolve() if args.run_root else (
        PROJECT / "verification" / "results" /
        datetime.datetime.now().strftime("%Y%m%dT%H%M%S")).resolve())
    run_root.mkdir(parents=True, exist_ok=True)
    cases = build_cases(run_root, args.binary, args.tracer)
    if args.list:
        for c in cases:
            print(f"{c.group:12s} {c._case_name:44s} {c.stop or '-':22s} {c.description[:60]}")
        return 0
    if args.group:
        cases = [c for c in cases if c.group == args.group]
    if args.case:
        cases = [c for c in cases if c._case_name in args.case]
    if not cases:
        print("no cases selected", file=sys.stderr)
        return 2

    results = []
    for spec in cases:
        name = spec._case_name
        runs = []
        for attempt in range(args.repeat):
            # Rebuild the case so every repeat starts from a clean Context.
            fresh = _rebuild(spec, cases, name)
            materialize(fresh, run_root)
            if args.repeat > 1 and attempt > 0:
                fresh.ctx.root = run_root / "repeat" / f"r{attempt + 1}"
                fresh.ctx.case_name = name
                fresh.ctx.dir = fresh.ctx.root / "cases" / name
                fresh.ctx.dir.mkdir(parents=True, exist_ok=True)
                fresh.ctx.artifacts = fresh.ctx.dir / "artifacts"
                fresh.ctx.artifacts.mkdir(parents=True, exist_ok=True)
                fresh.ctx.data_dir = fresh.ctx.root / "work" / name / "source"
                fresh.ctx.data_dir.parent.mkdir(parents=True, exist_ok=True)
            print(f"[run] {name}" + (f" ({attempt + 1}/{args.repeat})"
                                     if args.repeat > 1 else ""), flush=True)
            rec = runner.run_case(fresh, args.binary, args.tracer, fresh.ctx.root)
            rec["case"] = name
            rec["group"] = fresh.group
            runs.append(rec)
            print(f"[done] {name}: {rec['observations'].get('classification')}"
                  + (f"  ERROR: {rec['error']}" if rec.get("error") else ""), flush=True)
        rec = runs[0]
        if args.repeat > 1:
            classes = [r["observations"].get("classification") for r in runs]
            confirmed = [r["observations"].get("commit_confirmed")
                         for r in runs]
            rec["repeat"] = {
                "count": args.repeat,
                "classifications": classes,
                "confirmed": confirmed,
                "consistent": len(set(classes)) == 1,
            }
            rec["observations"]["repeat_consistent"] = len(set(classes)) == 1
            rec["runs"] = [{"classification": c,
                            "confirmed": cf,
                            "error": r.get("error")}
                           for c, cf, r in zip(classes, confirmed, runs)]
        results.append(rec)

    repeats = {}
    for rec in results:
        if "repeat" in rec:
            repeats[rec["case"]] = rec["repeat"]
    summary = {
        "repeat": args.repeat,
        "repeat_summary": {
            "cases": len(repeats),
            "consistent": sum(1 for v in repeats.values() if v["consistent"]),
            "inconsistent": [k for k, v in repeats.items()
                             if not v["consistent"]],
        } if repeats else None,
        "run_root": str(run_root),
        "binary": args.binary,
        "binary_sha256": _sha256(args.binary),
        "tracer": args.tracer,
        "tracer_sha256": _sha256(args.tracer),
        "started_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "cases": [{k: r.get(k) for k in
                   ("case", "group", "path_under_test", "description",
                    "stop", "corrupt_flip", "deterministic_boundary", "error",
                    "observations", "fault_fired", "repeat")} for r in results],
        "results": results,
    }
    (run_root / "matrix.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False))
    (run_root / "matrix.md").write_text(render_markdown(summary))
    try:
        import report
        (run_root / "OBSERVATIONS.md").write_text(report.render(run_root))
        print(f"wrote {run_root/'OBSERVATIONS.md'}")
    except Exception as exc:  # report is supplementary; never fail the run
        print(f"warning: report generation failed: {exc}", file=sys.stderr)
    print(f"\nwrote {run_root/'matrix.json'} and {run_root/'matrix.md'}")
    return 0


def _sha256(path):
    import hashlib
    try:
        return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    except Exception:
        return None


def _repeat_note(row):
    rep = row.get("repeat")
    if not rep:
        return "-"
    return "consistent" if rep["consistent"] else "INCONSISTENT"


def render_markdown(summary):
    lines = ["# LaminaDB durability fault matrix", "",
             f"- binary: `{summary['binary']}` sha256 `{summary['binary_sha256']}`",
             f"- tracer: `{summary['tracer']}` sha256 `{summary['tracer_sha256']}`",
             f"- run: `{summary['started_at']}`", "",
             "| case | path | boundary | confirmed | exact | repeat | classification | detail |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in summary["cases"]:
        o = row["observations"]
        confirmed = o.get("commit_confirmed")
        if confirmed is None:
            confirmed = o.get("checkpoint_confirmed")
        lines.append("| `{}` | {} | {} | {} | {} | {} | **{}** | {} |".format(
            row["case"], row["path_under_test"], row["stop"] or "-",
            "-" if confirmed is None else ("yes" if confirmed else "no"),
            "yes" if row.get("deterministic_boundary", True) else "no (racy)",
            _repeat_note(row),
            o.get("classification", "ERROR" if row.get("error") else "-"),
            (o.get("classification_detail") or row.get("error") or "").replace("|", "\\|")[:160]))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
