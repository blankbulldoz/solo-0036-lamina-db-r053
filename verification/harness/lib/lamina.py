"""Process control for the LaminaDB durability matrix.

The tracer is started in its own session; laminad puts itself in its own
process group (the tracer's child does setpgid). This keeps `killpg` from ever
touching the harness. The child pid is read back from the tracer's launch
event so the harness can hard-kill the database without killing the tracer.
"""
import json
import os
import pathlib
import signal
import socket
import subprocess
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Client:
    def __init__(self, port, timeout=10.0):
        self.port = port
        self.timeout = timeout
        self.url = f"http://127.0.0.1:{port}/v1/lamina"

    def call(self, method, path, data=None, timeout=None, raw=False):
        body = None if data is None else json.dumps(data, ensure_ascii=False).encode()
        req = urllib.request.Request(
            self.url + path, data=body, method=method,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                payload = r.read()
                return r.status, (payload if raw else json.loads(payload))
        except urllib.error.HTTPError as e:
            payload = e.read()
            try:
                return e.code, json.loads(payload)
            except Exception:
                return e.code, {"raw": payload.decode("utf-8", "replace")}
        except Exception as exc:
            return None, {"transport": type(exc).__name__, "detail": str(exc)}


def wait_ready(port, deadline_s=10.0, process=None):
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        if process is not None and process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{port}/v1/lamina/health", timeout=0.4) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.02)
    return False


class TracedProcess:
    def __init__(self, tracer, binary, data_dir, evidence, snapdir, stop=None,
                 watch=None, arm=None, extra_bin_args=None, log_path=None,
                 corrupt_flip=False):
        self.tracer = str(tracer)
        self.binary = str(pathlib.Path(binary).resolve())
        self.data_dir = pathlib.Path(data_dir).resolve()
        self.evidence = pathlib.Path(evidence).resolve()
        self.snapdir = pathlib.Path(snapdir).resolve()
        self.stop = stop
        self.corrupt_flip = corrupt_flip
        self.watch = watch or [str(self.data_dir) + "/*"]
        self.arm = pathlib.Path(arm).resolve() if arm else None
        self.extra_bin_args = extra_bin_args or []
        self.log_path = pathlib.Path(log_path).resolve() if log_path else None
        self.port = free_port()
        self.process = None
        self.child_pid = None
        self._log = None

    def start(self):
        self.data_dir.parent.mkdir(parents=True, exist_ok=True)
        self.evidence.parent.mkdir(parents=True, exist_ok=True)
        if self.arm:
            self.arm.unlink(missing_ok=True)
        self.snapdir.mkdir(parents=True, exist_ok=True)
        args = [self.tracer, "--evidence", str(self.evidence)]
        for w in self.watch:
            args += ["--watch", w]
        args += ["--snapshot-dir", str(self.snapdir)]
        if self.arm:
            args += ["--arm", str(self.arm)]
        if self.stop:
            args += ["--stop", self.stop]
        if self.corrupt_flip:
            args += ["--corrupt-flip"]
        args += ["--", self.binary, "-data", str(self.data_dir),
                 "-listen", f"127.0.0.1:{self.port}"] + self.extra_bin_args
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log = open(self.log_path, "wb")
        self.process = subprocess.Popen(
            args, stdout=self._log or subprocess.DEVNULL,
            stderr=subprocess.STDOUT if self._log else subprocess.DEVNULL,
            start_new_session=True)
        return self

    def client(self):
        return Client(self.port)

    def arm_now(self):
        if self.arm:
            self.arm.write_text("arm\n")

    def fault_fired(self):
        return _has_event(self.evidence, "fault")

    def wait_fault(self, timeout=10.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if _has_event(self.evidence, "fault"):
                return True
            if self.process.poll() is not None:
                return _has_event(self.evidence, "fault")
            time.sleep(0.02)
        return False

    def child_pid_from_evidence(self):
        if self.child_pid is None:
            for e in _events(self.evidence):
                if e.get("event") == "launch":
                    self.child_pid = e.get("pid")
                    break
        return self.child_pid

    def hard_kill_child(self):
        pid = self.child_pid_from_evidence()
        if pid:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception:
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass

    def hard_kill_child_graceful_first(self):
        pid = self.child_pid_from_evidence()
        if pid:
            try:
                os.killpg(pid, signal.SIGTERM)
            except Exception:
                pass

    def wait(self, timeout=20.0):
        try:
            return self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self):
        if self.process and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except Exception:
                self.process.kill()

    def close(self):
        if self.process and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except Exception:
                self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.kill()
        if self._log:
            self._log.close()
            self._log = None
        if self.arm:
            self.arm.unlink(missing_ok=True)


class PlainProcess:
    def __init__(self, binary, data_dir, extra_bin_args=None, log_path=None):
        self.binary = str(pathlib.Path(binary).resolve())
        self.data_dir = pathlib.Path(data_dir).resolve()
        self.extra_bin_args = extra_bin_args or []
        self.log_path = pathlib.Path(log_path).resolve() if log_path else None
        self.port = free_port()
        self.process = None
        self._log = None

    def start(self):
        self.data_dir.parent.mkdir(parents=True, exist_ok=True)
        args = [self.binary, "-data", str(self.data_dir),
                "-listen", f"127.0.0.1:{self.port}"] + self.extra_bin_args
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log = open(self.log_path, "wb")
        self.process = subprocess.Popen(
            args, stdout=self._log or subprocess.DEVNULL,
            stderr=subprocess.STDOUT if self._log else subprocess.DEVNULL,
            start_new_session=True)
        return self

    def client(self):
        return Client(self.port)

    def wait_ready(self, timeout=10.0):
        return wait_ready(self.port, timeout, self.process)

    def stop(self, timeout=12.0):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.kill()
        if self._log:
            self._log.close()
            self._log = None

    def kill(self):
        if self.process and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except Exception:
                self.process.kill()

    def log_text(self, limit=4000):
        if self.log_path and self.log_path.exists():
            return self.log_path.read_text(errors="replace")[-limit:]
        return ""


def _events(path):
    path = pathlib.Path(path)
    if not path.exists():
        return
    for line in path.read_text(errors="replace").splitlines():
        try:
            yield json.loads(line)
        except Exception:
            continue


def _has_event(path, name):
    return any(e.get("event") == name for e in _events(path))
