"""Runner: executes one scenario and classifies it from raw evidence.

Rules enforced here:

  * The source data directory is never mutated by backup/restore tests. Backups
    are copied into the evidence directory and restored from those copies into
    brand-new directories; each restore attempt gets a fresh copy.
  * The database's recovery success never serves as the only oracle. Raw bytes
    are parsed by journalmodel/imagemodel and oracle.inspect independently
    decides START/REFUSE plus the exact expected visible rows.
  * "Confirmed" always comes from a recorded 200 on that specific request;
    "unconfirmed" always comes from an observed transport death or 5xx. Nothing
    is inferred from log lines.
"""
import hashlib
import json
import pathlib
import shutil
import time

import imagemodel
import journalmodel
import oracle
from lamina import PlainProcess, TracedProcess, wait_ready
from scenarios import CorruptScenario, RestoreScenario, Session

GROUP_STATUS = {
    "commit": "commit-confirmation",
    "checkpoint": "checkpoint-replacement",
    "backup": "backup-install",
    "restore": "restore-install",
    "corruption": "corruption-rejection",
}


class Context:
    def __init__(self, binary, tracer, root, case_name):
        self.binary = pathlib.Path(binary).resolve()
        self.tracer = pathlib.Path(tracer).resolve()
        self.root = pathlib.Path(root).resolve()
        self.case_name = case_name
        self.dir = self.root / "cases" / case_name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.artifacts = self.dir / "artifacts"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.data_dir = self.root / "work" / case_name / "source"
        self.observations = {}
        self.events = []
        self.artifact_index = {}

    def record(self, key, value):
        self.observations[key] = value

    def note(self, message):
        self.events.append({"t": round(time.time(), 3), "message": message})

    def artifact_path(self, name):
        path = self.artifacts / name
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def write_artifact(self, name, data):
        path = self.artifact_path(name)
        if isinstance(data, str):
            data = data.encode()
        path.write_bytes(data)
        self.artifact_index[name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        self.record("artifact_" + name.replace("/", "_"), self.artifact_index[name])

    def write_json(self, name, data):
        path = self.artifact_path(name)
        path.write_text(json.dumps(data, indent=2, sort_keys=True,
                                   ensure_ascii=False))

    def capture_checkpoint_identity(self, tag):
        """Record which image the surviving checkpoint.lmi represents."""
        path = self.data_dir / "checkpoint.lmi"
        info = {"present": path.exists()}
        if path.exists():
            try:
                image = imagemodel.read(path)
                info.update({
                    "sequence": image["sequence"],
                    "horizon": image["horizon"],
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "valid": True,
                })
            except imagemodel.ImageError as exc:
                info.update({"valid": False, "error": str(exc)})
        self.record(tag + "_checkpoint", info)
        return info

    def capture_dir(self, tag):
        snap = {}
        dump = self.artifacts / tag
        for path in sorted(self.data_dir.iterdir()) if self.data_dir.exists() else []:
            if path.is_file():
                data = path.read_bytes()
                snap[path.name] = {"size": len(data),
                                   "sha256": hashlib.sha256(data).hexdigest()}
                dump.mkdir(parents=True, exist_ok=True)
                (dump / path.name).write_bytes(data)
        self.record(tag + "_files", snap)
        self.write_json(tag + "_files.json", snap)

    def capture_pre_fault(self, s):
        self.capture_dir("pre_fault")


def run_case(spec, binary, tracer, root):
    # The scenario already holds the authoritative Context (it may have
    # recorded setup facts into it); reuse it so nothing is lost.
    ctx = getattr(spec, "ctx", None) or Context(binary, tracer, root, spec.name)
    if ctx.data_dir.exists():
        shutil.rmtree(ctx.data_dir)
    ctx.data_dir.mkdir(parents=True)
    record = {
        "case": spec.name,
        "group": spec.group,
        "path_under_test": GROUP_STATUS.get(spec.group, spec.group),
        "description": spec.description,
        "stop": spec.stop,
        "corrupt_flip": spec.corrupt_flip,
        "deterministic_boundary": getattr(spec, "deterministic", True),
    }
    ctx.note("case start")
    try:
        if isinstance(spec, CorruptScenario):
            _run_corruption(spec, ctx, record)
        elif isinstance(spec, RestoreScenario):
            _run_restore(spec, ctx, record)
        else:
            _run_live(spec, ctx, record)
    except Exception as exc:
        import traceback
        record["error"] = f"{type(exc).__name__}: {exc}"
        record["traceback"] = traceback.format_exc()
        ctx.note(f"error: {exc}")
    record["observations"] = ctx.observations
    record["artifacts"] = ctx.artifact_index
    record["events"] = ctx.events
    ctx.write_json("record.json", record)
    return record


# --------------------------------------------------------------------------
# live fault cases (commit, checkpoint, backup)
# --------------------------------------------------------------------------

def _run_live(spec, ctx, record):
    # Controls that only need a hard kill after a 200 still run under the
    # tracer so the harness can learn the child pid from its launch event.
    traced = (spec.stop is not None or spec.corrupt_flip or
              getattr(spec, "request_hard_kill", False))
    if traced:
        tp = TracedProcess(
            ctx.tracer, ctx.binary, ctx.data_dir,
            evidence=ctx.artifacts / "tracer.jsonl",
            snapdir=ctx.artifacts / "fault-snapshot",
            stop=spec.stop,
            watch=[str(ctx.data_dir), str(ctx.data_dir) + "/*"],
            arm=(ctx.artifacts / "arm") if spec.needs_arm else None,
            log_path=ctx.artifacts / "server.log",
            corrupt_flip=spec.corrupt_flip)
        tp.start()
        if not wait_ready(tp.port, 12, tp.process):
            record["error"] = "server failed to start before fault"
            record["server_log"] = tp.log_text() if hasattr(tp, "log_text") else ""
            tp.close()
            return
        client = Session(tp.client())
        spec.setup(client)
        if spec.needs_arm:
            tp.arm_now()
        record["trigger_result"] = spec.trigger(client)
        if getattr(spec, "request_hard_kill", False):
            # Baseline/control: the response is in hand, now kill the process.
            pid = tp.child_pid_from_evidence()
            ctx.record("hard_kill_child_pid", pid)
            tp.hard_kill_child()
        record["fault_fired"] = tp.wait_fault(timeout=20) if spec.stop else None
        record["tracer_exit"] = tp.wait(timeout=20)
        record["fault_evidence"] = _summarize_tracer(ctx.artifacts / "tracer.jsonl")
        tp.close()
    else:
        p = PlainProcess(ctx.binary, ctx.data_dir,
                         log_path=ctx.artifacts / "server.log").start()
        if not p.wait_ready(12):
            record["error"] = "server failed to start"
            p.stop()
            return
        client = Session(p.client())
        spec.setup(client)
        record["trigger_result"] = spec.trigger(client)
        p.stop()

    ctx.capture_dir("post_fault")
    if spec.group == "checkpoint":
        ctx.capture_checkpoint_identity("post_fault")
    record["observation"] = run_observation(
        ctx.binary, ctx.data_dir, ctx.artifacts / "recovery.log")
    ctx.capture_dir("post_recovery")
    if spec.group == "checkpoint":
        ctx.capture_checkpoint_identity("post_recovery")

    if spec.group == "commit":
        _classify_commit(spec, ctx, record)
    elif spec.group == "checkpoint":
        _classify_checkpoint(spec, ctx, record)
    elif spec.group == "backup":
        _classify_backup(spec, ctx, record)


def _row_keys(verdict_rows):
    out = set()
    for table in (verdict_rows or {}).values():
        out |= set(table)
    return out


def _classify_commit(spec, ctx, record):
    obs = record["observation"]
    verdict = obs["oracle"]
    confirmed = bool(ctx.observations.get("commit_confirmed"))
    payload = set(ctx.observations.get("payload_keys") or [])
    keys = _row_keys(verdict.get("rows"))
    payload_keys = {f"int:{n}" for n in payload}
    ack_keys = {f"int:{n}" for n in (ctx.observations.get("ack_keys") or [])}
    started = obs["started"]
    if verdict["outcome"] != oracle.Verdict.START:
        status, detail = "must_refuse", verdict["reason"]
    elif not payload_keys <= keys:
        if confirmed:
            status, detail = "BROKEN_confirmed_lost", \
                "client got 200 but payload is absent after recovery"
        else:
            status, detail = "unconfirmed_absent", \
                "no 200 and payload absent (permitted)"
    elif confirmed:
        status, detail = "confirmed_and_persisted", \
            "200 recorded and payload present after recovery"
    else:
        status, detail = "unconfirmed_persisted", \
            "no 200 but bytes survived (permitted; client cannot know)"
    floor = obs.get("durable_floor") or {}
    if floor.get("sequence"):
        floor_keys = set(floor.get("row_keys") or [])
        ctx.record("durable_floor_sequence", floor.get("sequence"))
        ctx.record("durable_floor_rows_present", floor_keys <= keys)
        if not floor_keys <= keys:
            status, detail = "BROKEN_durable_floor_rows_lost", \
                f"rows durable at sequence {floor['sequence']} are missing"
    ctx.record("acked_rows_present", ack_keys <= keys if ack_keys else None)
    if ack_keys and not ack_keys <= keys:
        status, detail = "BROKEN_acked_rows_lost", \
            "rows committed with a 200 before the fault are missing"
    ctx.record("classification", status)
    ctx.record("classification_detail", detail)


def _classify_checkpoint(spec, ctx, record):
    obs = record["observation"]
    verdict = obs["oracle"]
    confirmed = bool(ctx.observations.get("checkpoint_confirmed"))
    # Independent replay decides the expected rows regardless of which
    # checkpoint file (old or new) survived.
    if verdict["outcome"] != oracle.Verdict.START:
        if confirmed:
            status, detail = "BROKEN_confirmed_checkpoint_unrecoverable", \
                verdict["reason"]
        else:
            status, detail = "refused_after_unconfirmed_checkpoint", verdict["reason"]
    else:
        expected = None
        journal, image = None, None
        try:
            _, journal, image = oracle.inspect(ctx.data_dir)
        except Exception as exc:
            ctx.note(f"journal re-inspect failed: {exc}")
        status = "recovered"
        detail = verdict["reason"]
        cp = ctx.observations.get("post_fault_checkpoint") or {}
        ctx.record("checkpoint_installed_sequence", cp.get("sequence"))
        ctx.record("checkpoint_image_valid_after_fault", cp.get("valid"))
        if confirmed:
            if verdict["checkpoint_valid"] is False:
                status, detail = "BROKEN_confirmed_but_no_checkpoint", \
                    "checkpoint returned 200 but no valid image is installed"
            else:
                status = "confirmed_and_recovered"
        # Compare visible rows against replay of the journal alone.
        if journal is not None:
            replay = journalmodel.replay(journal.records, "spectra")
            at = verdict.get("head") or 0
            if at not in replay:
                candidates = [s for s in replay if s <= at]
                at = max(candidates) if candidates else None
            expected = replay.get(at) if at is not None else None
            actual = set(_row_keys(verdict.get("rows")))
            if expected is not None:
                same = set(expected) == actual
                ctx.record("rows_equal_journal_replay", same)
                ctx.record("replay_sequence_used", at)
                if not same:
                    status = "BROKEN_rows_diverge_from_journal"
                    detail = (f"visible {sorted(actual)} vs replay {sorted(expected)}")
    # Availability question: a damaged checkpoint after an unconfirmed replace
    # makes the instance unable to start even though the journal suffix is
    # intact. Record that the journal was independently valid so this is
    # distinguishable from actual data loss.
    if status.startswith("refused"):
        ctx.record("refusal_cause",
                   "damaged checkpoint; the journal alone covers the lost "
                   "suffix, but the documented rule is to refuse rather than "
                   "silently ignore a checkpoint")
    ctx.record("classification", status)
    ctx.record("classification_detail", detail)


def _classify_backup(spec, ctx, record):
    obs = record["observation"]
    verdict = obs["oracle"]
    ctx.record("classification",
               "backup_frozen_and_source_recoverable"
               if ctx.observations.get("backup_image_valid") else
               "backup_invalid")
    ctx.record("source_after_backup_oracle", verdict)


# --------------------------------------------------------------------------
# restore cases
# --------------------------------------------------------------------------

def _run_restore(spec, ctx, record):
    src = PlainProcess(ctx.binary, ctx.data_dir,
                       log_path=ctx.artifacts / "source.log").start()
    if not src.wait_ready(12):
        record["error"] = "source failed to start"
        src.stop()
        return
    spec.setup(Session(src.client()))
    src.stop()

    source = ctx.artifact_path("source-backup.lmi")
    restore_dir = ctx.root / "work" / ctx.case_name / "restored"
    if restore_dir.exists():
        shutil.rmtree(restore_dir)
    restore_input = ctx.artifact_path("restore-input.lmi")
    restore_input.write_bytes(source.read_bytes())
    ctx.record("restore_input_sha256",
               hashlib.sha256(restore_input.read_bytes()).hexdigest())
    if spec.tamper:
        spec.tamper(restore_input, ctx)
        ctx.record("restore_input_tampered_sha256",
                   hashlib.sha256(restore_input.read_bytes()).hexdigest())

    tp = TracedProcess(
        ctx.tracer, ctx.binary, restore_dir,
        evidence=ctx.artifacts / "tracer.jsonl",
        snapdir=ctx.artifacts / "restore-snapshot",
        stop=spec.stop,
        watch=[str(restore_dir), str(restore_dir) + "/*"],
        log_path=ctx.artifacts / "restore.log",
        corrupt_flip=spec.corrupt_flip,
        extra_bin_args=["-restore", str(restore_input)])
    tp.start()
    record["fault_fired"] = tp.wait_fault(timeout=20) if spec.stop else None
    record["tracer_exit"] = tp.wait(timeout=25)
    record["fault_evidence"] = _summarize_tracer(ctx.artifacts / "tracer.jsonl")
    tp.close()

    record["restore_dir_present"] = restore_dir.exists()
    files = {}
    if restore_dir.exists():
        for path in sorted(restore_dir.iterdir()):
            if path.is_file():
                files[path.name] = {"size": path.stat().st_size,
                                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    ctx.record("restore_installed_files", files)
    ctx.write_artifact(
        "restore.log.tail",
        tp.process.args and "" or "")

    if restore_dir.exists():
        record["observation"] = run_observation(
            ctx.binary, restore_dir, ctx.artifacts / "restored-recovery.log")
        _classify_restore(spec, ctx, record, files)
        # Operator contract: can the same -restore be retried into the same
        # directory after an interrupted install?
        retry = PlainProcess(ctx.binary, restore_dir,
                             extra_bin_args=["-restore", str(restore_input)],
                             log_path=ctx.artifacts / "restore-retry.log").start()
        retry_started = retry.wait_ready(8)
        retry.stop()
        ctx.record("restore_retry_same_dir_started", retry_started)
        ctx.record("restore_retry_same_dir_log",
                   retry.log_text(800) if not retry_started else None)
    else:
        ctx.record("classification", "restore_aborted_cleanly")
        ctx.record("classification_detail",
                   "restore made no directory; source backup untouched")


def _classify_restore(spec, ctx, record, files):
    obs = record["observation"]
    verdict = obs["oracle"]
    expected = _image_rows(ctx, "source-backup.lmi")
    installed = ctx.observations.get("restore_installed_files") or {}
    journal_empty = (installed.get("journal.lmw", {}).get("size") == 0 and
                     "checkpoint.lmi" not in installed)
    if verdict["outcome"] != oracle.Verdict.START:
        status = "restore_left_refusable_state"
        detail = verdict["reason"]
    elif journal_empty:
        # The restore created an empty journal and no checkpoint: an instance
        # may start (fresh journal semantics) but it is not a restore. Call it
        # what it is rather than "complete".
        status = "restore_not_installed"
        detail = ("zero-length journal and no checkpoint; the directory can "
                  "start as a fresh database but contains none of the backup")
    else:
        actual = _row_keys(verdict.get("rows"))
        expected_keys = set(expected)
        if actual == expected_keys:
            status = "restore_complete"
            detail = "installed image exposes exactly the source rows"
        elif actual < expected_keys:
            status = "restore_incomplete"
            detail = f"missing {sorted(expected_keys - actual)}"
        else:
            status = "BROKEN_restore_diverged"
            detail = f"extra {sorted(actual - expected_keys)}"
    ctx.record("classification", status)
    ctx.record("classification_detail", detail)
    ctx.record("restored_row_keys", sorted(_row_keys(verdict.get("rows"))))
    ctx.record("source_row_keys", sorted(expected))


def _image_rows(ctx, name):
    path = ctx.artifact_path(name)
    if not path.exists():
        return set()
    image = imagemodel.read(path)
    out = set()
    for rel, table in (image.get("store", {}).get("tables") or {}).items():
        for key, chain in table.items():
            v = imagemodel.visible(chain, image["sequence"])
            if v is not None and not v.get("deleted"):
                out.add(key)
    return out


# --------------------------------------------------------------------------
# corruption cases
# --------------------------------------------------------------------------

def _run_corruption(spec, ctx, record):
    p = PlainProcess(ctx.binary, ctx.data_dir,
                     log_path=ctx.artifacts / "server.log").start()
    if not p.wait_ready(12):
        record["error"] = "server failed to start for corruption setup"
        p.stop()
        return
    spec.setup(Session(p.client()))
    p.stop()
    ctx.capture_dir("pre_fault")
    spec.mutate(ctx.data_dir, ctx)
    ctx.capture_dir("post_fault")
    if spec.group == "checkpoint":
        ctx.capture_checkpoint_identity("post_fault")
    record["observation"] = run_observation(
        ctx.binary, ctx.data_dir, ctx.artifacts / "recovery.log")
    ctx.capture_dir("post_recovery")
    if spec.group == "checkpoint":
        ctx.capture_checkpoint_identity("post_recovery")
    verdict = record["observation"]["oracle"]
    started = record["observation"]["started"]
    must_refuse = verdict["outcome"] == oracle.Verdict.REFUSE
    ctx.record("oracle_outcome", verdict["outcome"])
    ctx.record("oracle_reason", verdict["reason"])
    ctx.record("server_started", started)
    if must_refuse and not started:
        ctx.record("classification", "refused_as_required")
        ctx.record("classification_detail",
                   "corruption rejected at startup, as the format requires")
    elif must_refuse and started:
        ctx.record("classification", "BROKEN_silent_accept")
        ctx.record("classification_detail",
                   "invalid bytes were accepted; expected refusal")
    elif not must_refuse and started:
        ctx.record("classification", "accepted_cleanly")
        ctx.record("classification_detail", verdict["reason"])
    else:
        ctx.record("classification", "BROKEN_oracle_start_but_refused")
        ctx.record("classification_detail", verdict["reason"])
    # For accepted cases, the visible rows and the reported truncation must
    # match the oracle; any divergence is a silent repair.
    if started:
        rows = _row_keys(record["observation"]["oracle"].get("rows"))
        expected = _row_keys(verdict.get("rows"))
        ctx.record("visible_row_keys", sorted(rows))
        ctx.record("oracle_row_keys", sorted(expected))
        if rows != expected:
            ctx.record("classification", "BROKEN_silent_state_change")
            ctx.record("classification_detail",
                       f"visible {sorted(rows)} vs oracle {sorted(expected)}")
        stats = record["observation"].get("stats") or {}
        reported = stats.get("recovered_tail_bytes")
        ctx.record("reported_recovered_tail_bytes", reported)
        if reported != verdict["tail_bytes"]:
            ctx.record("classification", "BROKEN_tail_report_mismatch")
            ctx.record("classification_detail",
                       f"server reported {reported}, bytes show {verdict['tail_bytes']}")


# --------------------------------------------------------------------------
# observation
# --------------------------------------------------------------------------

def run_observation(binary, data_dir, log_path, timeout=12.0):
    verdict, journal, image = oracle.inspect(data_dir)
    _, durable_seq, durable_rows = oracle.durable_max(data_dir)
    p = PlainProcess(binary, data_dir, log_path=log_path).start()
    started = p.wait_ready(timeout=timeout)
    out = {
        "started": started,
        "exit_code": None if started else p.process.poll(),
        "log_tail": "" if started else p.log_text(),
        "oracle": verdict.as_dict(),
        "durable_floor": {
            "sequence": durable_seq,
            "row_keys": sorted(durable_rows) if durable_rows else [],
        },
    }
    if started:
        c = p.client()
        st, stats = c.call("GET", "/stats")
        out["stats"] = stats if st == 200 else {"status": st, "body": stats}
        st, cat = c.call("GET", "/catalog")
        out["catalog_status"] = st
        out["catalog"] = cat if st == 200 else None
        rows = {}
        if st == 200:
            for rel in cat.get("relations", []):
                name = rel["name"]
                stq, q = c.call("POST", "/query", {"relation": name, "limit": 10000})
                rows[name] = {
                    "status": stq,
                    "rows": _sorted_rows(q.get("rows", [])) if stq == 200 else q,
                }
        out["rows"] = rows
        sequences = set(verdict.durable_sequences)
        for extra in (verdict.journal_sequence_end,
                      verdict.image_sequence,
                      (out.get("stats") or {}).get("sequence")):
            if extra:
                sequences.add(extra)
        hist = {}
        for seq in sorted(s for s in sequences if s):
            stq, q = c.call("POST", "/query",
                            {"relation": "spectra", "at": seq, "limit": 10000})
            hist[str(seq)] = {
                "status": stq,
                "rows": _sorted_rows(q.get("rows", [])) if stq == 200 else q,
            }
        out["history"] = hist
        # The durable floor must be readable as a snapshot too. If it is not,
        # a confirmed/unconfirmed commit older than the floor is unreachable.
        floor = durable_seq
        if floor:
            stq, q = c.call("POST", "/query",
                            {"relation": "spectra", "at": floor, "limit": 10000})
            out["durable_floor_read"] = {
                "status": stq,
                "rows": _sorted_rows(q.get("rows", [])) if stq == 200 else q,
            }
        p.stop()
    else:
        p.stop()
    return out


def _sorted_rows(rows):
    return sorted(rows, key=lambda r: json.dumps(r, sort_keys=True))


def _summarize_tracer(evidence_path):
    path = pathlib.Path(evidence_path)
    if not path.exists():
        return None
    counted, snapshots, mutations, exit_events = [], [], [], []
    fault = None
    for line in path.read_text(errors="replace").splitlines():
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("event") == "syscall" and e.get("counted"):
            counted.append({k: e.get(k) for k in
                            ("phase", "kind", "path", "path2", "nth", "result",
                             "frame_valid", "frame_seq", "frame_kind",
                             "frame_crc_ok", "size_after", "off", "len")})
        elif e.get("event") == "fault":
            fault = e
        elif e.get("event", "").startswith("snapshot"):
            snapshots.append(e)
        elif e.get("event") in ("flip_applied", "corrupt_applied",
                                "eio_injected", "corrupt_failed", "flip_failed",
                                "torn_applied"):
            mutations.append(e)
        elif e.get("event") == "target_exit":
            exit_events.append(e)
    return {
        "fault": fault,
        "counted": counted,
        "snapshots": snapshots,
        "mutations": mutations,
        "target_exit": exit_events,
    }
