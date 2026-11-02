"""Offline test policy for Breaker: a Python-level guard plus the pytest plugin that applies it.

WHAT THE DEFAULT RUN DOES
  * Offline is the default and needs no flag. Integration tests run only with the explicit ``--integration`` command-line
    option. No environment variable, credential, endpoint or Docker daemon can switch them on: ``integration_enabled()``
    reads one in-process flag that only that option sets.
  * Inherited credentials and service settings (N8N_*, MCP_*, DOCKER_*, *_API_KEY, tokens, ...) are removed from this
    process's environment before anything else is imported, and the names removed are reported (never the values).
  * The guard is installed before conftest imports anything, so collection and import-time side effects are covered, not
    only test bodies.

WHAT THE GUARD BLOCKS (Python level)
  * ``socket`` connects (``connect``, ``connect_ex``, ``create_connection``) except to a loopback port that THIS process
    bound itself (the local fake servers some tests start), and DNS lookups of any name that is not loopback;
  * ``subprocess`` (every ``Popen``, hence ``run``/``call``/``check_output``), ``os.system``/``os.popen``/``os.startfile``/
    ``os.spawn*`` and ``webbrowser`` opens, except ``git`` (local sub-commands only) and the running Python interpreter
    (its children get the same guard through a ``sitecustomize`` on ``PYTHONPATH``; isolated/``-E``/``-S`` children are
    refused because they would skip it).
  A blocked attempt raises ``OfflineViolation`` (an ``OSError``) AND is recorded. The session fails at the end if anything
  was recorded, even when the test swallowed the exception, so a violation can never end as a clean pass.

WHAT IT DOES NOT PROVIDE (the protection boundary)
  This is not operating-system network isolation. A monkeypatch cannot see: C extensions that open sockets themselves,
  ``_winapi.CreateProcess``/``ctypes`` calls, ``_overlapped``/``_winapi`` pipe opens that do not go through ``open``/``os.open``,
  or a child process that is not Python or git (those are refused, not guarded). The asyncio proactor ``sock_connect``,
  UDP ``sendto`` and ``open``/``os.open`` of a named pipe or docker socket path ARE checked. For absolute isolation run the suite in a network-less container/VM or behind an OS firewall rule as well.
"""
from __future__ import annotations

import builtins
import io
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tempfile
import webbrowser
from contextlib import contextmanager
from pathlib import Path

BANNER = "OFFLINE-GUARD:"
CHILD_REPORT_ENV = "BREAKER_OFFLINE_GUARD_CHILD_REPORT"
PORTS_ENV = "BREAKER_OFFLINE_GUARD_PORTS"
#: loopback ports that belong to real services: never reachable, even if a test happened to bind one
SERVICE_PORTS = frozenset({25, 587, 1025, 2375, 2376, 3306, 5432, 5678, 6379, 8025})
#: loopback ports that are closed by definition; connecting only proves "unreachable" (a test of failure handling)
UNREACHABLE_PORTS = frozenset({1})
#: names that carry credentials or point at live services; removed from the environment in offline mode
SCRUB = re.compile(r"(N8N|MCP_|DOCKER|NGROK|API_?KEY|TOKEN|SECRET|PASSW|CREDENTIAL|BREAKER_ALLOW_LIVE|BREAKER_S4|"
                   r"BREAKER_INTEGRATION|SUPABASE|VERCEL|GITHUB|(^|_)GH_|AWS_|AZURE_|GOOGLE_|ANTHROPIC|OPENAI|GROQ|STRIPE|"
                   r"SMTP|TWILIO|SLACK|WEBHOOK_URL)", re.IGNORECASE)
ALLOWED_PROGRAMS = {"git", "python", "python3", "py"}
GIT_NETWORK = {"push", "fetch", "pull", "clone", "ls-remote", "remote", "submodule", "archive", "send-email", "daemon"}
LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}


class OfflineViolation(OSError):
    """An offline-mode test tried to reach outside the process. Recorded, and the session fails."""


_state = {"installed": False, "open": False, "integration": False, "child": False, "violations": [], "expected": [],
          "scrubbed": [], "excluded": [], "ports": set(), "orig": {}, "withheld": {}, "report": None, "sitecustomize": None}


# ------------------------------------------------------------------------------------------------------------------
# recording
# ------------------------------------------------------------------------------------------------------------------
def _record(what: str) -> None:
    record = {"what": what, "test": os.environ.get("PYTEST_CURRENT_TEST", "<collection/import>")[:200], "child": _state["child"]}
    _state["violations"].append(record)
    path = os.environ.get(CHILD_REPORT_ENV)
    if _state["child"] and not _state.get("session") and path:  # a child pytest session reports through its own exit status
        try:
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record) + "\n")
        except OSError:
            pass


def violation(what: str):
    _record(what)
    raise OfflineViolation(f"offline guard blocked: {what}")


@contextmanager
def expect_violations():
    """For the guard's own negative tests only: violations raised inside are moved to a visible ``expected`` list."""
    start, child_file = len(_state["violations"]), os.environ.get(CHILD_REPORT_ENV)
    child_start = Path(child_file).stat().st_size if child_file and Path(child_file).is_file() else 0
    try:
        yield
    finally:
        _state["expected"].extend(_state["violations"][start:])
        del _state["violations"][start:]
        if child_file and Path(child_file).is_file() and Path(child_file).stat().st_size > child_start:
            data = Path(child_file).read_bytes()
            _state["expected"].extend(json.loads(line) for line in data[child_start:].decode("utf-8").splitlines() if line.strip())
            Path(child_file).write_bytes(data[:child_start])


def integration_enabled() -> bool:
    """True only when the run was started with ``--integration``. Never derived from the environment."""
    return bool(_state["integration"] and _state["open"])


# ------------------------------------------------------------------------------------------------------------------
# checks
# ------------------------------------------------------------------------------------------------------------------
def _host_port(address):
    if isinstance(address, (tuple, list)) and len(address) >= 2:
        return str(address[0]), address[1]
    return None, None




def _check_path(path) -> None:
    if _state["open"]:
        return
    try:
        text = os.fsdecode(path).replace("/", "\\").lower() if isinstance(path, (str, bytes, os.PathLike)) else ""
    except (TypeError, ValueError):
        return
    pipe = chr(92) * 2 + "." + chr(92) + "pipe" + chr(92)  # the Windows named-pipe namespace; other device paths (NUL, ...) are fine
    if text.startswith(pipe) or "docker_engine" in text or "docker.sock" in text:
        violation(f"open of service endpoint {text[:60]!r}")


def _check_connect(address) -> None:
    if _state["open"]:
        return
    host, port = _host_port(address)
    if host is not None and (host in LOOPBACK or host.startswith("127.")) and port not in SERVICE_PORTS:
        if port in _state["ports"] or port in UNREACHABLE_PORTS or port in _shared_ports():
            return
    violation(f"socket connect to {address!r}")


def _shared_ports() -> set[int]:
    """Loopback ports bound anywhere in this process tree (a test's own receiver, reached by a child script it launched)."""
    path = os.environ.get(PORTS_ENV)
    if not path or not Path(path).is_file():
        return set()
    try:
        return {int(x) for x in Path(path).read_text(encoding="utf-8").split() if x.isdigit()}
    except OSError:
        return set()


def _refuse_command(args, shell) -> str | None:
    if shell:
        return f"shell command {str(args)[:60]!r}"
    if isinstance(args, (str, bytes, os.PathLike)):
        try:
            parts = shlex.split(os.fsdecode(args), posix=False)
        except ValueError:
            return f"unparseable command {str(args)[:60]!r}"
    else:
        parts = [os.fsdecode(a) for a in args]
    if not parts:
        return "empty command"
    program = Path(parts[0].strip('"')).name.lower()
    stem = program[:-4] if program.endswith(".exe") else program
    exe = os.path.normcase(os.path.abspath(sys.executable))
    is_python = stem in ("python", "python3", "py") or os.path.normcase(os.path.abspath(parts[0].strip('"'))) == exe
    if not (is_python or stem in ALLOWED_PROGRAMS):
        return f"process {stem!r}"
    if is_python and any(a.startswith("-") and not a.startswith("--") and set(a[1:]) & {"I", "E", "S"} for a in parts[1:3]):
        return "isolated python child (would skip the guard)"
    if stem == "git":
        rest, skip = [], False
        for a in parts[1:]:
            if skip:
                skip = False
            elif a in ("-C", "-c", "--git-dir", "--work-tree"):
                skip = True
            elif not a.startswith("-"):
                rest.append(a)
        if rest and rest[0] in GIT_NETWORK:
            return f"git {rest[0]} (network sub-command)"
    return None


def _child_env(env):
    """The environment a child Python gets: the same guard, injected through a sitecustomize on PYTHONPATH."""
    directory = _state["sitecustomize"]
    if directory is None:
        return env
    base = dict(os.environ if env is None else env)
    base["PYTHONPATH"] = os.pathsep.join(filter(None, [str(directory), base.get("PYTHONPATH", "")]))
    base.setdefault(CHILD_REPORT_ENV, os.environ.get(CHILD_REPORT_ENV, ""))
    return base


def _make_sitecustomize() -> Path:
    directory = Path(tempfile.mkdtemp(prefix="breaker-offline-guard-"))
    repo = Path(__file__).resolve().parents[1]
    (directory / "sitecustomize.py").write_text(
        "import sys\n"
        f"sys.path.insert(0, {str(repo)!r})\n"
        "try:\n"
        "    from tools import offline_guard as g\n"
        "    g.install(child=True)\n"
        "except Exception:\n"
        "    raise SystemExit('offline guard could not start in a child interpreter')\n", encoding="utf-8")
    return directory


# ------------------------------------------------------------------------------------------------------------------
# install / open / uninstall
# ------------------------------------------------------------------------------------------------------------------
def scrub_environment() -> list[str]:
    names = sorted(n for n in os.environ if SCRUB.search(n))
    for name in names:
        _state["withheld"][name] = os.environ.pop(name)  # kept in memory only, so --integration can restore them
    _state["scrubbed"] = names
    return names


def install(child: bool = False) -> None:
    if _state["installed"]:
        return
    _state["installed"], _state["child"] = True, child
    orig = _state["orig"]
    scrub_environment()
    if not child:
        report = Path(tempfile.mkdtemp(prefix="breaker-offline-report-")) / "children.jsonl"
        os.environ[CHILD_REPORT_ENV] = str(report)
        os.environ[PORTS_ENV] = str(report.with_name("ports.txt"))
        _state["sitecustomize"] = _make_sitecustomize()
        os.environ["PYTHONPATH"] = os.pathsep.join(filter(None, [str(_state["sitecustomize"]), os.environ.get("PYTHONPATH", "")]))
    orig.update(sendto=socket.socket.sendto, bi_open=builtins.open, io_open=io.open, os_open=os.open,
                connect=socket.socket.connect, connect_ex=socket.socket.connect_ex, bind=socket.socket.bind,
                create_connection=socket.create_connection, getaddrinfo=socket.getaddrinfo,
                popen_init=subprocess.Popen.__init__, system=os.system, popen=os.popen,
                startfile=getattr(os, "startfile", None), wb_open=webbrowser.open,
                wb_new=webbrowser.open_new, wb_tab=webbrowser.open_new_tab)

    def connect(self, address):
        _check_connect(address)
        return orig["connect"](self, address)

    def connect_ex(self, address):
        _check_connect(address)
        return orig["connect_ex"](self, address)

    def sendto(self, data, *args):
        if args:
            _check_connect(args[-1])
        return orig["sendto"](self, data, *args)

    def guarded_open(file, *a, **k):
        if isinstance(file, (str, bytes, os.PathLike)):
            _check_path(file)
        return orig["bi_open"](file, *a, **k)

    def guarded_os_open(path, *a, **k):
        _check_path(path)
        return orig["os_open"](path, *a, **k)

    def bind(self, address):
        result = orig["bind"](self, address)
        host, _ = _host_port(address)
        if host is not None and (host in LOOPBACK or host.startswith("127.")):
            port = self.getsockname()[1]
            _state["ports"].add(port)
            shared = os.environ.get(PORTS_ENV)
            if shared:
                try:
                    with open(shared, "a", encoding="utf-8") as handle:
                        handle.write(f"{port}" + chr(10))
                except OSError:
                    pass
        return result

    def create_connection(address, *a, **k):
        _check_connect(address)
        return orig["create_connection"](address, *a, **k)

    def getaddrinfo(host, *a, **k):
        if not _state["open"] and str(host) not in LOOPBACK and not str(host).startswith("127."):
            violation(f"DNS lookup of {host!r}")
        return orig["getaddrinfo"](host, *a, **k)

    def popen_init(self, args, *a, **k):
        if not _state["open"]:
            reason = _refuse_command(args, k.get("shell") or (a[7] if len(a) > 7 else False))
            if reason:
                violation(f"subprocess: {reason}")
            k["env"] = _child_env(k.get("env"))
        return orig["popen_init"](self, args, *a, **k)

    def refuse(label):
        def blocked(*a, **k):
            if _state["open"] and orig.get(label):
                return orig[label](*a, **k)
            violation(f"{label}{a[:1]!r}")
        return blocked

    socket.socket.connect, socket.socket.connect_ex, socket.socket.bind = connect, connect_ex, bind
    socket.socket.sendto = sendto
    builtins.open = io.open = guarded_open
    os.open = guarded_os_open
    try:  # the Windows proactor loop connects through ConnectEx, which never calls socket.connect
        from asyncio import proactor_events as _pe
        orig["proactor_connect"] = _pe.BaseProactorEventLoop.sock_connect

        async def sock_connect(self, sock, address):
            _check_connect(address)
            return await orig["proactor_connect"](self, sock, address)
        _pe.BaseProactorEventLoop.sock_connect = sock_connect
    except (ImportError, AttributeError):  # pragma: no cover
        pass
    socket.create_connection, socket.getaddrinfo = create_connection, getaddrinfo
    subprocess.Popen.__init__ = popen_init
    os.system, os.popen = refuse("system"), refuse("popen")
    if orig["startfile"] is not None:
        os.startfile = refuse("startfile")
    webbrowser.open, webbrowser.open_new, webbrowser.open_new_tab = refuse("wb_open"), refuse("wb_new"), refuse("wb_tab")
    for name in ("spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
        if hasattr(os, name):
            orig[name] = getattr(os, name)
            setattr(os, name, refuse(name))


def open_guard() -> None:
    """Explicit integration opt-in: lift the guard and give back the credentials that were withheld."""
    _state["open"] = True
    os.environ.update(_state["withheld"])


def uninstall() -> None:
    """Restore everything (used by the guard's own tests)."""
    if not _state["installed"]:
        return
    o = _state["orig"]
    socket.socket.connect, socket.socket.connect_ex, socket.socket.bind = o["connect"], o["connect_ex"], o["bind"]
    socket.socket.sendto = o["sendto"]
    builtins.open, io.open, os.open = o["bi_open"], o["io_open"], o["os_open"]
    if "proactor_connect" in o:
        from asyncio import proactor_events as _pe
        _pe.BaseProactorEventLoop.sock_connect = o["proactor_connect"]
    socket.create_connection, socket.getaddrinfo = o["create_connection"], o["getaddrinfo"]
    subprocess.Popen.__init__ = o["popen_init"]
    os.system, os.popen = o["system"], o["popen"]
    if o.get("startfile") is not None:
        os.startfile = o["startfile"]
    webbrowser.open, webbrowser.open_new, webbrowser.open_new_tab = o["wb_open"], o["wb_new"], o["wb_tab"]
    for name in ("spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
        if name in o:
            setattr(os, name, o[name])
    os.environ.update(_state["withheld"])
    _state.update(installed=False, open=False, integration=False, violations=[], expected=[], scrubbed=[], excluded=[],
                  ports=set(), orig={}, withheld={})


# ------------------------------------------------------------------------------------------------------------------
# pytest plugin
# ------------------------------------------------------------------------------------------------------------------
def load_policy(root: Path, path: str | None = None) -> dict:
    target = Path(path) if path else root / "config" / "offline-test-policy.json"
    if not target.is_file():
        raise RuntimeError(f"offline test policy not found: {target}")
    data = json.loads(target.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("live_nodes"), list) or not isinstance(data.get("reviewed_files"), dict):
        raise RuntimeError(f"offline test policy is malformed: {target}")
    return data


def pytest_addoption(parser):
    group = parser.getgroup("breaker offline policy")
    group.addoption("--integration", action="store_true", default=False,
                    help="run tests that need a live n8n/Docker/notification service (never enabled by the environment)")
    group.addoption("--breaker-guard-report", default=None, help="write the guard report (JSON) here")
    group.addoption("--breaker-offline-policy", default=None, help="path of the offline test policy (default config/offline-test-policy.json)")


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: needs a live service; excluded unless --integration is given")
    if not _state["installed"]:
        install()  # a run that did not import the guard from conftest still gets it before collection
    _state["session"] = True
    os.environ.pop("PYTEST_CURRENT_TEST", None)  # a nested session must not inherit the outer test's name
    _state["integration"] = bool(config.getoption("--integration"))
    if _state["integration"]:
        open_guard()
    _state["report"] = config.getoption("--breaker-guard-report")
    config._breaker_policy = load_policy(Path(str(config.rootpath)), config.getoption("--breaker-offline-policy"))


def pytest_collection_modifyitems(config, items):
    if integration_enabled():
        return
    live = {entry["node"]: entry["reason"] for entry in config._breaker_policy["live_nodes"]}
    keep, dropped = [], []
    for item in items:
        why = live.get(item.nodeid) or ("marked integration" if item.get_closest_marker("integration") else None)
        (dropped if why else keep).append(item)
        if why:
            _state["excluded"].append({"node": item.nodeid, "reason": why})
    if dropped:
        config.hook.pytest_deselected(items=dropped)
        items[:] = keep


def _children() -> list[dict]:
    path = os.environ.get(CHILD_REPORT_ENV)
    if not path or not Path(path).is_file():
        return []
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def summary_lines() -> list[str]:
    mode = "integration (guard open)" if integration_enabled() else "offline"
    return [f"{BANNER} active mode={mode} violations={len(_state['violations']) + len(_children())} "
            f"expected_in_guard_tests={len(_state['expected'])} excluded={len(_state['excluded'])} "
            f"env_names_withheld={len(_state['scrubbed'])}"]


def pytest_terminal_summary(terminalreporter):
    for line in summary_lines():
        terminalreporter.write_line(line)
    for record in _state["violations"] + _children():
        terminalreporter.write_line(f"{BANNER} VIOLATION in {record['test']}: {record['what']}")
    for entry in _state["excluded"]:
        terminalreporter.write_line(f"{BANNER} EXCLUDED {entry['node']} ({entry['reason']})")


def pytest_sessionfinish(session, exitstatus):
    violations = _state["violations"] + _children()
    if _state["report"]:
        Path(_state["report"]).write_text(json.dumps({
            "mode": "integration" if integration_enabled() else "offline", "violations": violations,
            "expected_in_guard_tests": _state["expected"], "excluded": _state["excluded"],
            "env_names_withheld": _state["scrubbed"], "exit_status": int(exitstatus)}, indent=2), encoding="utf-8")
    if violations and int(exitstatus) == 0:
        session.exitstatus = 1  # a violation can never end as a clean pass, even if the test swallowed it


# ------------------------------------------------------------------------------------------------------------------
# static classification: a test file that can reach outside the process must have been reviewed
# ------------------------------------------------------------------------------------------------------------------
RUNTIME_CONSTRUCTS = re.compile(
    r"(\bdocker\b|N8N_(BASE_URL|API_KEY|MCP)|MCP_N8N|N8nMcpTestTransport|localhost|127\.0\.0\.1|urlopen|urllib\.request|"
    r"http\.client|requests\.(get|post|put|delete|request|Session)|\bhttpx\b|aiohttp|\bsocket\b\.|socketserver|http\.server|"
    r"HTTPServer|subprocess|Popen|os\.system|os\.popen|startfile|webbrowser)")
REVIEW_CLASSES = ("OFFLINE_FAKE", "OFFLINE_LOOPBACK_SERVER", "OFFLINE_PYTHON_OR_GIT_CHILD", "OFFLINE_STATIC_REFERENCE", "LIVE_OPT_IN")


def scan_runtime_dependent(repo: Path) -> dict[str, list[int]]:
    """test file (repo-relative) -> line numbers that mention a construct able to reach outside the process."""
    found: dict[str, list[int]] = {}
    for path in sorted((repo / "tests").rglob("*.py")):
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        hits = [i + 1 for i, line in enumerate(lines) if RUNTIME_CONSTRUCTS.search(line) and not line.lstrip().startswith("#")]
        if hits:
            found[path.relative_to(repo).as_posix()] = hits
    return found


def unclassified(repo: Path, policy: dict) -> list[str]:
    """Runtime-dependent test files with no reviewed entry (exact path or glob) in the policy: the gate fails closed on these."""
    reviewed = policy["reviewed_files"]
    from fnmatch import fnmatch
    missing = []
    for rel in scan_runtime_dependent(repo):
        entry = reviewed.get(rel) or next((v for k, v in reviewed.items() if "*" in k and fnmatch(rel, k)), None)
        if not entry or entry.get("class") not in REVIEW_CLASSES or not str(entry.get("basis", "")).strip():
            missing.append(rel)
    return missing
