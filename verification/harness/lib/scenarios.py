"""Scenario definitions for the LaminaDB durability fault matrix.

Each persistence path (commit confirmation, checkpoint replacement, backup
restore) is bracketed at the syscalls that make it durable. A scenario only
describes setup + trigger; classification lives in runner.py and is derived
from raw evidence, never from the server's self-report alone.

Vocabulary used in reports:

  confirmed    the client received a 200 for this mutation.
  unconfirmed  the client received a transport error or 5xx, or the process
               died before any response. The bytes may or may not be durable.
  must_refuse  the on-disk bytes are not a valid state; a correct instance
               must reject startup rather than silently repair or accept.
"""
import json

import imagemodel

RELATION = "spectra"
SCHEMA = {
    "name": RELATION,
    "primary": "sample",
    "columns": [
        {"name": "sample", "type": "int"},
        {"name": "band", "type": "text"},
        {"name": "amplitude", "type": "int", "nullable": True},
        {"name": "valid", "type": "bool"},
    ],
}


def row(n, amplitude=None, band=None, valid=True):
    return {"sample": n, "band": band or f"b{n}",
            "amplitude": n * 10 if amplitude is None else amplitude,
            "valid": valid}


class Session:
    """Scenario-facing wrapper over the public HTTP client."""

    def __init__(self, client):
        self.client = client

    def call(self, method, path, data=None, status=None, raw=False, timeout=None):
        st, body = self.client.call(method, path, data, raw=raw, timeout=timeout)
        if status is not None and st != status:
            raise AssertionError(
                f"{method} {path}: expected {status}, got {st}: {body}")
        return st, body

    def begin(self, readonly=False):
        st, body = self.call("POST", "/transactions", {"read_only": readonly},
                             status=201)
        return body["id"]

    def put(self, tx, row_value, status=None):
        return self.call("POST", f"/transactions/{tx}/put",
                         {"relation": RELATION, "row": row_value}, status=status)

    def delete(self, tx, key, status=None):
        return self.call("POST", f"/transactions/{tx}/delete",
                         {"relation": RELATION, "key": key}, status=status)

    def commit(self, tx, status=None):
        return self.call("POST", f"/transactions/{tx}/commit", status=status,
                         timeout=20)

    def query(self, **kwargs):
        st, body = self.call("POST", "/query", {"relation": RELATION, **kwargs})
        return body

    def stats(self):
        st, body = self.call("GET", "/stats")
        return body


class Scenario:
    name = "base"
    group = "misc"
    stop = None
    corrupt_flip = False
    needs_arm = True
    deterministic = True
    description = ""

    def __init__(self, ctx):
        self.ctx = ctx
        self.ack_rows = []

    def setup(self, s):
        s.call("POST", "/relations", SCHEMA, status=201)
        seed = s.begin()
        for n in (1, 2, 3):
            s.put(seed, row(n))
        s.commit(seed)
        s.call("POST", "/checkpoint")     # establish an image base
        tx = s.begin()
        for n in (4, 5):
            s.put(tx, row(n))
        s.commit(tx)                      # and a journal suffix
        if self.ack_rows:
            tx = s.begin()
            for r in self.ack_rows:
                s.put(tx, r)
            self.ctx.record("ack_commit", s.commit(tx)[1])
        self.ctx.record("setup_head", s.stats()["sequence"])
        self.ctx.capture_pre_fault(s)

    def trigger(self, s):
        raise NotImplementedError


class CommitScenario(Scenario):
    """Kill at a commit-durability boundary.

    ack_rows are committed and acknowledged before arming; payload_rows are the
    commit whose confirmation is under test.
    """

    group = "commit"
    needs_arm = True

    def __init__(self, ctx, payload_rows, stop, description="",
                 ack_rows=None, corrupt_flip=False):
        super().__init__(ctx)
        self.payload_rows = payload_rows
        self.stop = stop
        self.description = description
        self.ack_rows = ack_rows or []
        self.corrupt_flip = corrupt_flip
        self.deterministic = not (stop or "").startswith("abort-")

    def trigger(self, s):
        tx = s.begin()
        for r in self.payload_rows:
            s.put(tx, r)
        st, body = s.call("POST", f"/transactions/{tx}/commit", timeout=20)
        self.ctx.record("commit_http_status", st)
        self.ctx.record("commit_http_body", body)
        self.ctx.record("commit_confirmed", st == 200)
        self.ctx.record("payload_keys", sorted(r["sample"] for r in self.payload_rows))
        self.ctx.record("ack_keys", sorted(r["sample"] for r in self.ack_rows))
        if st is not None and st >= 500:
            # The instance must stop serving after an uncertain durable write.
            sx, bx = s.call("POST", "/transactions", {})
            qx, qb = s.call("POST", "/query", {"relation": RELATION, "limit": 10})
            self.ctx.record("post_failure_begin", {"status": sx, "body": bx})
            self.ctx.record("post_failure_query", {"status": qx, "body": qb})
        return st, body


class AckThenKillScenario(CommitScenario):
    name = "commit-baseline-ack-then-kill"
    request_hard_kill = False
    """Control: commit acknowledged, then a hard kill with no pending work.

    This is deliberately *not* a fault-boundary case; it is the baseline that
    proves a 200 really means durable, so the matrix can distinguish it from
    an unconfirmed commit.
    """

    description = ("Baseline: commit returns 200, process is SIGKILLed "
                   "immediately after the response. Rows must survive.")
    stop = None
    needs_arm = False

    def __init__(self, ctx):
        super().__init__(ctx, [row(20), row(21)], stop=None,
                         description=self.description)

    def trigger(self, s):
        tx = s.begin()
        for r in self.payload_rows:
            s.put(tx, r)
        st, body = s.call("POST", f"/transactions/{tx}/commit")
        self.ctx.record("commit_http_status", st)
        self.ctx.record("commit_http_body", body)
        self.ctx.record("commit_confirmed", st == 200)
        self.ctx.record("payload_keys", [r["sample"] for r in self.payload_rows])
        self.ctx.record("ack_keys", [])
        if st != 200:
            raise AssertionError(
                f"control commit was not acknowledged: {st} {body}")
        self.request_hard_kill = True
        return st, body


class AckThenKillCheckpoint(Scenario):
    """Control: checkpoint acknowledged, then an unannounced SIGKILL."""

    name = "checkpoint-baseline-ack-then-kill"
    group = "checkpoint"
    corrupt_flip = False
    stop = None
    needs_arm = False
    description = ("Control: checkpoint returns 200, then SIGKILL. The installed "
                   "image must be the acknowledged one and must equal journal "
                   "replay at its sequence.")

    def __init__(self, ctx):
        super().__init__(ctx)
        self.request_hard_kill = False

    def setup(self, s):
        super().setup(s)
        self.ctx.record("stats_before_checkpoint", s.stats())

    def trigger(self, s):
        st, body = s.call("POST", "/checkpoint")
        self.ctx.record("checkpoint_http_status", st)
        self.ctx.record("checkpoint_http_body", body)
        self.ctx.record("checkpoint_confirmed", st == 200)
        self.ctx.record("checkpoint_sequence",
                        body.get("sequence") if isinstance(body, dict) else None)
        if st != 200:
            raise AssertionError(
                f"control checkpoint was not acknowledged: {st} {body}")
        self.request_hard_kill = True
        return st, body


class CheckpointScenario(Scenario):
    """Kill at a checkpoint-replacement boundary.

    The checkpoint path is: write temp -> fsync(temp) -> rename -> fsync(dir).
    The data directory itself is watched so both fsyncs are counted:
      N=1 -> temp file fsync, N=2 -> directory fsync.
    """

    group = "checkpoint"
    needs_arm = True   # arm after setup so only checkpoint syscalls count

    def __init__(self, ctx, stop, description="", corrupt_flip=False,
                 payload_rows=None, label=None, repeat=1):
        super().__init__(ctx)
        self.stop = stop
        self.corrupt_flip = corrupt_flip
        self.description = description
        self.payload_rows = payload_rows or [row(10), row(11)]
        self.label = label
        self.repeat = repeat

    def setup(self, s):
        super().setup(s)
        tx = s.begin()
        for r in self.payload_rows:
            s.put(tx, r)
        s.commit(tx)
        self.ctx.record("checkpoint_head", s.stats()["sequence"])
        self.ctx.capture_pre_fault(s)

    def trigger(self, s):
        results = []
        for i in range(self.repeat):
            st, body = s.call("POST", "/checkpoint", timeout=20)
            results.append({"status": st, "body": body})
            self.ctx.record(f"checkpoint_http_status_{i + 1}", st)
            self.ctx.record(f"checkpoint_http_body_{i + 1}", body)
        self.ctx.record("checkpoint_http_status", results[0]["status"])
        self.ctx.record("checkpoint_http_body", results[0]["body"])
        self.ctx.record("checkpoint_confirmed",
                        all(r["status"] == 200 for r in results))
        self.ctx.record("checkpoint_responses", results)
        return results


class BackupScenario(Scenario):
    """Fetch a backup while the source keeps serving; never mutate the source."""

    group = "backup"
    needs_arm = False

    def __init__(self, ctx, description="", during_rows=None):
        super().__init__(ctx)
        self.description = description
        self.during_rows = during_rows or []

    def trigger(self, s):
        if self.during_rows:
            tx = s.begin()
            for r in self.during_rows:
                s.put(tx, r)
            st, body = s.call("POST", f"/transactions/{tx}/commit")
            self.ctx.record("concurrent_commit_status", st)
        st, body = s.call("GET", "/backup", raw=True, timeout=20)
        self.ctx.record("backup_http_status", st)
        if st != 200:
            raise AssertionError(f"backup failed: {st} {body!r}")
        if isinstance(body, bytes):
            self.ctx.write_artifact("backup.lmi", body)
            self.ctx.write_artifact("backup-bytes-unchanged-check.bin", body)
            self.ctx.record("backup_bytes", len(body))
            self.ctx.record("backup_sha256", __import__("hashlib").sha256(body).hexdigest())
            try:
                image = imagemodel.decode(body)
                self.ctx.record("backup_image_sequence", image["sequence"])
                self.ctx.record("backup_image_horizon", image["horizon"])
                self.ctx.record("backup_image_valid", True)
                # The source must equal an independent replay at that sequence.
                from oracle import inspect as oracle_inspect
                verdict, journal, checkpoint = oracle_inspect(self.ctx.data_dir)
                expected = None
                if journal is not None:
                    import journalmodel
                    snaps = journalmodel.replay(journal.records, RELATION)
                    expected = snaps.get(image["sequence"])
                actual = {k: v for k, v in
                          _image_rows(image, RELATION).items()}
                if expected is not None:
                    self.ctx.record("backup_matches_journal_replay",
                                    actual == expected)
                    self.ctx.record("backup_expected_rows",
                                    sorted(expected))
                    self.ctx.record("backup_actual_rows", sorted(actual))
            except imagemodel.ImageError as exc:
                self.ctx.record("backup_image_valid", False)
                self.ctx.record("backup_image_error", str(exc))
            # A later source commit must not change bytes already handed out.
            tx = s.begin()
            s.put(tx, row(400))
            s.call("POST", f"/transactions/{tx}/commit")
            again = self.ctx.artifact_path("backup.lmi").read_bytes()
            self.ctx.record("backup_bytes_stable_after_source_write",
                            __import__("hashlib").sha256(again).hexdigest() ==
                            self.ctx.observations.get("artifact_backup.lmi", {}).get("sha256"))
            st2, body2 = s.call("GET", "/backup", raw=True)
            self.ctx.record("second_backup_status", st2)
            try:
                image2 = imagemodel.decode(body2)
                self.ctx.record("second_backup_sequence", image2["sequence"])
                self.ctx.record("second_backup_has_new_row",
                                any(k == "int:400" for k in
                                    _image_rows(image2, RELATION)))
            except imagemodel.ImageError as exc:
                self.ctx.record("second_backup_error", str(exc))
        else:
            self.ctx.record("backup_body", body)


def _image_rows(image, relation):
    out = {}
    for key, chain in (image.get("store", {}).get("tables", {})
                       .get(relation, {})).items():
        v = imagemodel.visible(chain, image["sequence"])
        if v is not None and not v.get("deleted"):
            out[key] = v["row"]
    return out


class RestoreScenario(Scenario):
    """Take a clean backup, then inject a fault while installing it.

    The source database is stopped before restore. The backup bytes live in
    the evidence directory (not under any data directory), so restore faults
    cannot corrupt the source backup; a fresh copy is used per attempt.
    """

    group = "restore"
    needs_arm = False

    def __init__(self, ctx, stop, description="", corrupt_flip=False,
                 backup_rows=None, tamper=None, label=None):
        super().__init__(ctx)
        self.stop = stop
        self.corrupt_flip = corrupt_flip
        self.description = description
        self.backup_rows = backup_rows or [row(1), row(2), row(3)]
        self.tamper = tamper
        self.label = label

    def setup(self, s):
        s.call("POST", "/relations", SCHEMA, status=201)
        tx = s.begin()
        for r in self.backup_rows:
            s.put(tx, r)
        s.commit(tx)
        # an index makes the image carry catalog metadata too
        s.call("POST", "/indexes",
               {"name": "by_band", "relation": RELATION, "column": "band",
                "unique": False}, status=201)
        st, body = s.call("GET", "/backup", raw=True)
        assert st == 200, (st, body)
        self.ctx.write_artifact("source-backup.lmi", body)
        self.ctx.record("source_backup_bytes", len(body))
        self.ctx.record("source_backup_sha256",
                        __import__("hashlib").sha256(body).hexdigest())
        image = imagemodel.decode(body)
        self.ctx.record("source_backup_sequence", image["sequence"])
        self.ctx.write_json("source-backup-decoded.json", image)
        self.ctx.record("backup_rows", sorted(_image_rows(image, RELATION)))
        # freeze the bytes used by restore into a copy the DB never wrote
        self.ctx.artifact_path("restore-input.lmi").write_bytes(body)

    def trigger(self, s):
        pass


class CorruptScenario(Scenario):
    """No live process at fault time: damage a completed data directory."""

    group = "corruption"
    stop = None
    needs_arm = False

    def __init__(self, ctx, mutate, description="", label=""):
        super().__init__(ctx)
        self.mutate = mutate
        self.description = description
        self.label = label
        self.name = "corrupt-" + label

    def trigger(self, s):
        pass
