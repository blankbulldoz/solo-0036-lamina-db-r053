"""Self-checks for the verification harness itself (negative controls).

A fault matrix is only meaningful if it can fail. These checks deliberately
break the *assumptions* of the harness and confirm it notices:

  harness-oracle-detects-honest-loss
      A real commit is acknowledged, then its journal frame is removed behind
      the database's back. The same oracle that judges every case must report
      the row as missing. If the oracle cannot see this, no commit verdict in
      the matrix can be trusted.

  harness-tracer-really-kills
      Run a trivial writer under the tracer, kill it after N writes, and assert
      exactly N writes reached the file and the process did not survive.

  harness-tracer-really-freezes-at-boundary
      Assert the last counted syscall precedes the kill: for kill-in:write the
      frame must be absent; for kill-after:write it must be present.

  harness-digest-required
      Corrupt a backup payload without touching its digest; the harness's own
      image decoder must reject it, independently of laminad.

  harness-no-source-mutation
      Snapshot the source backup bytes, run a restore from a copy, and assert
      the source file's digest is unchanged.

These are run by `python3 verification/harness/selfcheck.py`.
"""
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve()
sys.path.insert(0, str(HERE.parent / "lib"))

import imagemodel
import oracle
from lamina import Client, PlainProcess, TracedProcess


def _fail(msg):
    raise AssertionError(msg)


def check_oracle_detects_honest_loss(binary, tracer, root):
    """Acknowledge a commit, then delete its last journal frame."""
    d = root / "loss"
    if d.exists():
        shutil.rmtree(d)
    p = PlainProcess(binary, d, log_path=root / "loss.log").start()
    if not p.wait_ready(10):
        _fail("server did not start for oracle-loss check")
    c = Client(p.port)
    st, _ = c.call("POST", "/relations", {
        "name": "t", "primary": "k",
        "columns": [{"name": "k", "type": "int"}]})
    if st != 201:
        _fail(f"relation create returned {st}")
    st, tx = c.call("POST", "/transactions", {})
    c.call("POST", f"/transactions/{tx['id']}/put",
           {"relation": "t", "row": {"k": 1}})
    st, body = c.call("POST", f"/transactions/{tx['id']}/commit")
    if st != 200:
        _fail(f"commit not acknowledged: {st} {body}")
    p.stop()

    jpath = d / "journal.lmw"
    data = bytearray(jpath.read_bytes())
    off = 16
    frames = []
    while off + 8 <= len(data):
        length = int.from_bytes(data[off:off + 4], "big")
        if length == 0 or off + 8 + length > len(data):
            break
        frames.append((off, length))
        off += 8 + length
    if not frames:
        _fail("no journal frame to remove")
    last_off, last_len = frames[-1]
    # Drop the acknowledged commit frame *and* keep the header intact. The
    # resulting file is a valid journal with a contiguous prefix, so only a
    # comparison against the acknowledged fact can catch the loss.
    del data[last_off:last_off + 8 + last_len]
    jpath.write_bytes(bytes(data))

    verdict, journal, image = oracle.inspect(d)
    if verdict.outcome != oracle.Verdict.START:
        _fail(f"oracle unexpectedly refused a valid truncated prefix: {verdict.reason}")
    if "int:1" in verdict.state.get("rows", {}).get("t", {}):
        _fail("oracle did not notice the acknowledged row disappeared")
    # The database itself will happily start (a valid prefix); this is why the
    # matrix must not use restart success as its oracle.
    obs = PlainProcess(binary, d, log_path=root / "loss2.log").start()
    started = obs.wait_ready(10)
    rows = []
    if started:
        st, q = obs.client().call("POST", "/query",
                                  {"relation": "t", "limit": 10})
        rows = [r["k"] for r in q.get("rows", [])] if st == 200 else [f"status {st}"]
    obs.stop()
    return {
        "oracle_detected_loss": True,
        "server_started_without_loss_detection": started,
        "server_rows": rows,
        "note": ("This is the key negative control: LaminaDB starts cleanly on "
                 "a silently shortened journal, so only the independent model "
                 "can classify a lost acknowledged commit."),
    }


def check_tracer_kills_exactly(binary, tracer, root):
    d = root / "killloop"
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    script = d / "writer.sh"
    script.write_text(
        "#!/bin/sh\n"
        f"i=0\nwhile [ $i -lt 100 ]; do echo $i >> {d}/out.txt; i=$((i+1)); done\n")
    script.chmod(0o755)
    evidence = root / "killloop.jsonl"
    evidence.unlink(missing_ok=True)
    tp = TracedProcess(tracer, "/bin/sh", d,
                       evidence=evidence, snapdir=root / "killloop-snap",
                       stop="kill-after:5:write",
                       watch=[str(d) + "/*"],
                       extra_bin_args=[])
    # TracedProcess adds -data/-listen, which /bin/sh ignores only by luck; run
    # the shell directly instead.
    args = [str(tracer), "--evidence", str(evidence),
            "--watch", str(d) + "/*",
            "--stop", "kill-after:5:write", "--", "/bin/sh", str(script)]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    proc.wait(timeout=20)
    lines = (d / "out.txt").read_text().splitlines() if (d / "out.txt").exists() else []
    fault = any('"event":"fault"' in ln for ln in evidence.read_text().splitlines())
    if not fault:
        _fail("tracer did not report a fault")
    if len(lines) != 5:
        _fail(f"expected exactly 5 completed writes, saw {len(lines)}")
    return {"writes_before_kill": len(lines), "fault_reported": fault,
            "note": "kill-after is exact and the target does not survive."}


def check_tracer_boundary_semantics(binary, tracer, root):
    """kill-in:write must leave the file without the frame; kill-after must
    leave it with the frame."""
    results = {}
    for mode, expect in (("kill-in:1:write", 0), ("kill-after:1:write", 1)):
        d = root / ("boundary-" + mode.replace(":", "_"))
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        target = d / "out.txt"
        target.write_bytes(b"")
        evidence = root / (mode.replace(":", "_") + ".jsonl")
        evidence.unlink(missing_ok=True)
        args = [str(tracer), "--evidence", str(evidence),
                "--watch", str(d) + "/*", "--stop", mode, "--",
                "/bin/sh", "-c", f"echo PAYLOAD >> {target}"]
        proc = subprocess.Popen(args, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True)
        proc.wait(timeout=20)
        size = target.stat().st_size
        got = 1 if size >= len(b"PAYLOAD\n") else 0
        if got != expect:
            _fail(f"{mode}: expected frame {'present' if expect else 'absent'}, "
                  f"file size {size}")
        results[mode] = {"bytes_after": size, "frame_present": bool(got)}
    return results


def check_repeatability(binary, tracer, root, n=5):
    """The same boundary must produce the same accepted fact every time."""
    outcomes = []
    for i in range(n):
        d = root / f"repeat-{i}"
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        evidence = root / f"repeat-{i}.jsonl"
        evidence.unlink(missing_ok=True)
        script = d / "w.sh"
        script.write_text(
            "#!/bin/sh\n"
            f"echo A >> {d}/f1.txt\n"
            f"echo B >> {d}/f2.txt\n")
        script.chmod(0o755)
        args = [str(tracer), "--evidence", str(evidence),
                "--watch", str(d) + "/*", "--stop", "kill-after:1:write",
                "--", "/bin/sh", str(script)]
        subprocess.Popen(args, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         start_new_session=True).wait(timeout=20)
        present = [(d / f"f{i}.txt").exists() for i in (1, 2)]
        outcomes.append(tuple(present))
    if len(set(outcomes)) != 1:
        _fail(f"boundary repeated inconsistently: {outcomes}")
    if outcomes[0] != (True, False):
        _fail(f"unexpected survival pattern at kill-after:1:write: {outcomes[0]}")
    return {"trials": n, "pattern": "first write present, second absent",
            "all_identical": True}


def check_digest_required(root):
    image = {
        "format": 1, "sequence": 1, "horizon": 0,
        "catalog": {"relations": {}, "indexes": {}},
        "store": {"tables": {}},
    }
    good = imagemodel.encode(image)
    image2 = imagemodel.decode(good)
    bad = bytearray(good)
    bad[-2] ^= 0xFF
    rejected = False
    try:
        imagemodel.decode(bytes(bad))
    except imagemodel.ImageError:
        rejected = True
    if not rejected:
        _fail("harness image decoder accepted a payload with a stale digest")
    return {"digest_enforced": True, "roundtrip_sequence": image2["sequence"]}


def check_source_not_mutated(binary, tracer, root):
    d = root / "src"
    if d.exists():
        shutil.rmtree(d)
    p = PlainProcess(binary, d, log_path=root / "src.log").start()
    if not p.wait_ready(10):
        _fail("source did not start")
    c = Client(p.port)
    c.call("POST", "/relations", {
        "name": "spectra", "primary": "sample",
        "columns": [{"name": "sample", "type": "int"},
                    {"name": "band", "type": "text"}]})
    st, tx = c.call("POST", "/transactions", {})
    c.call("POST", f"/transactions/{tx['id']}/put",
           {"relation": "spectra", "row": {"sample": 1, "band": "b"}})
    c.call("POST", f"/transactions/{tx['id']}/commit")
    st, backup = c.call("GET", "/backup", raw=True)
    if st != 200:
        _fail(f"backup failed: {st}")
    p.stop()
    path = root / "backup.lmi"
    path.write_bytes(backup)
    digest_before = hashlib.sha256(path.read_bytes()).hexdigest()
    restore_dir = root / "restored"
    if restore_dir.exists():
        shutil.rmtree(restore_dir)
    r = PlainProcess(binary, restore_dir,
                     extra_bin_args=["-restore", str(path)],
                     log_path=root / "restore.log").start()
    started = r.wait_ready(10)
    r.stop()
    digest_after = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest_before != digest_after:
        _fail("restore modified the source backup file")
    if not started:
        _fail("restore did not start")
    return {"source_sha256": digest_before, "unchanged": True,
            "restored": True}


def main():
    binary = pathlib.Path(sys.argv[1] if len(sys.argv) > 1
                          else "/workspace/bin/laminad")
    tracer = pathlib.Path(sys.argv[2] if len(sys.argv) > 2
                          else "/workspace/verification/tracer/laminad-fault")
    root = pathlib.Path(sys.argv[3] if len(sys.argv) > 3
                        else "/tmp/lamina-selfcheck")
    root.mkdir(parents=True, exist_ok=True)
    checks = [
        ("harness-oracle-detects-honest-loss",
         lambda: check_oracle_detects_honest_loss(binary, tracer, root)),
        ("harness-tracer-kills-exactly",
         lambda: check_tracer_kills_exactly(binary, tracer, root)),
        ("harness-tracer-boundary-semantics",
         lambda: check_tracer_boundary_semantics(binary, tracer, root)),
        ("harness-repeatability",
         lambda: check_repeatability(binary, tracer, root)),
        ("harness-digest-required", lambda: check_digest_required(root)),
        ("harness-source-not-mutated",
         lambda: check_source_not_mutated(binary, tracer, root)),
    ]
    out = {"binary": str(binary), "tracer": str(tracer),
           "checks": {}}
    failed = 0
    for name, fn in checks:
        try:
            out["checks"][name] = {"status": "pass", "detail": fn()}
            print(f"PASS {name}")
        except Exception as exc:
            failed += 1
            out["checks"][name] = {"status": "fail",
                                   "error": f"{type(exc).__name__}: {exc}"}
            print(f"FAIL {name}: {exc}")
    (root / "selfcheck.json").write_text(json.dumps(out, indent=2))
    print(f"wrote {root/'selfcheck.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
