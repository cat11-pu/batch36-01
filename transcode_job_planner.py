class PlanError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


import hashlib
import json
import re
import subprocess

_ALLOWED_FIELDS = {"input_key", "output_key", "preset", "filters", "crf", "label"}
_REQUIRED_FIELDS = ("input_key", "output_key", "preset", "crf")
_INPUT_SUFFIX = ".mov"
_OUTPUT_SUFFIX = ".mp4"
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_LABEL_SAFE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_ .\-]*")
_FILTER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_FIXED_ENV_KEYS = ("PATH", "HOME")
_RUN_TIMEOUT = 30
_RUNNER_ERROR_CODE = "runner_error"


def _default_runner(argv, env, timeout, cwd):
    proc = subprocess.run(
        argv,
        env=env,
        timeout=timeout,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout


class TranscodeJobPlanner:
    def __init__(self, workdir, allowed_filters, presets=("fast", "medium", "slow"), runner=None):
        if not isinstance(workdir, str) or not workdir.startswith("/"):
            raise PlanError("bad_workdir")
        self._workdir = workdir.rstrip("/") or "/"
        self._allowed_filters = frozenset(allowed_filters)
        self._presets = tuple(presets)
        self._runner = runner if runner is not None else _default_runner
        self._issued = set()
        self._planned = 0
        self._ran = 0
        self._rejected = 0

    def _reject(self, code):
        self._rejected += 1
        raise PlanError(code)

    def _check_key(self, key, suffix):
        if not isinstance(key, str) or not key:
            self._reject("bad_path")
        if "\x00" in key:
            self._reject("nul_byte")
        if "\\" in key:
            self._reject("backslash")
        if _DRIVE_PREFIX.match(key):
            self._reject("drive_prefix")
        if key.startswith("/"):
            self._reject("absolute_path")
        segments = key.split("/")
        if any(seg == ".." for seg in segments):
            self._reject("parent_segment")
        if any(seg in ("", ".") for seg in segments):
            self._reject("bad_path")
        if not key.endswith(suffix):
            self._reject("bad_suffix")
        return self._workdir + "/" + key

    def _check_filters(self, filters):
        if filters is None:
            return []
        if not isinstance(filters, (list, tuple)):
            self._reject("bad_filter")
        checked = []
        for entry in filters:
            if not isinstance(entry, str) or not entry:
                self._reject("bad_filter")
            name, sep, value = entry.partition("=")
            if name not in self._allowed_filters:
                self._reject("filter_not_allowed")
            if not sep or not _FILTER_NAME.fullmatch(name):
                self._reject("bad_filter")
            if not value.isdigit():
                self._reject("bad_filter")
            checked.append(name + "=" + value)
        return checked

    def _check_label(self, label):
        if label is None:
            return ""
        if not isinstance(label, str):
            self._reject("bad_label")
        if label == "":
            return label
        if label.startswith("-"):
            self._reject("bad_label")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in label):
            self._reject("bad_label")
        if not _LABEL_SAFE.fullmatch(label):
            self._reject("bad_label")
        return label

    @staticmethod
    def _digest(plan):
        try:
            blob = json.dumps(plan, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            return None
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def plan(self, job, now=0):
        if not isinstance(job, dict):
            self._reject("bad_job")
        unknown = set(job) - _ALLOWED_FIELDS
        if unknown:
            self._reject("unknown_field")
        for field in _REQUIRED_FIELDS:
            if field not in job:
                self._reject("missing_field")

        input_path = self._check_key(job["input_key"], _INPUT_SUFFIX)
        output_path = self._check_key(job["output_key"], _OUTPUT_SUFFIX)
        filters = self._check_filters(job.get("filters"))

        preset = job["preset"]
        if preset not in self._presets:
            self._reject("bad_preset")

        crf = job["crf"]
        if isinstance(crf, bool) or not isinstance(crf, int) or not 0 <= crf <= 51:
            self._reject("bad_crf")

        label = self._check_label(job.get("label"))

        argv = ["ffmpeg", "-nostdin", "-y", "-i", input_path]
        if filters:
            argv += ["-vf", ",".join(filters)]
        argv += ["-preset", preset, "-crf", str(crf), output_path]

        plan = {"argv": argv, "output_path": output_path, "display": label}
        self._issued.add(self._digest(plan))
        self._planned += 1
        return plan

    def run(self, plan, now=0):
        if not isinstance(plan, dict):
            self._reject("tampered_plan")
        digest = self._digest(plan)
        if digest is None or digest not in self._issued:
            self._reject("tampered_plan")
        env = {"PATH": "/usr/bin", "HOME": self._workdir}
        try:
            code, stdout = self._runner(plan["argv"], env, _RUN_TIMEOUT, self._workdir)
        except Exception:
            return {"code": _RUNNER_ERROR_CODE, "stdout": ""}
        self._ran += 1
        return {"code": code, "stdout": _tail(stdout)}

    def snapshot(self):
        return {"planned": self._planned, "ran": self._ran, "rejected": self._rejected}


def _tail(stdout):
    if not isinstance(stdout, str):
        stdout = "" if stdout is None else str(stdout)
    lines = stdout.splitlines()
    return lines[-1] if lines else ""
