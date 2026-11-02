"""Negative and positive tests for the offline test guard. Nothing here contacts n8n, Docker or any service: every
attempt is either refused by the guard before it leaves the process, or aimed at a socket this test opened itself."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
import webbrowser
from pathlib import Path

import pytest

from tools import offline_guard as g

REPO = Path(__file__).resolve().parents[1]


def blocked():
    return g.expect_violations(), pytest.raises(g.OfflineViolation)


# ---- sockets ----------------------------------------------------------------------------------------------------------
def test_connecting_to_an_outside_address_is_refused_and_recorded():
    before = len(g._state["expected"])
    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        socket.create_connection(("192.0.2.1", 80), timeout=1)
    assert len(g._state["expected"]) == before + 1 and "192.0.2.1" in g._state["expected"][-1]["what"]


@pytest.mark.parametrize("port", [5678, 8025, 1025, 2375])
def test_loopback_service_ports_nobody_here_bound_are_refused(port):
    sock = socket.socket()
    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        sock.connect(("127.0.0.1", port))
    sock.close()
    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        sock.connect_ex(("localhost", port))


def test_a_loopback_server_the_test_started_itself_is_reachable():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    seen = []
    threading.Thread(target=lambda: seen.append(server.accept()[0].recv(4)), daemon=True).start()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        client.sendall(b"ping")
    server.close()
    assert port in g._state["ports"]


def test_dns_lookup_of_an_outside_name_is_refused_but_localhost_resolves():
    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        socket.getaddrinfo("example.com", 80)
    assert socket.getaddrinfo("localhost", 80)


def test_an_exception_swallowed_by_the_test_is_still_recorded():
    start = len(g._state["violations"])
    try:
        socket.create_connection(("192.0.2.9", 80), timeout=1)
    except Exception:  # noqa: BLE001 - what a careless test does
        pass
    assert len(g._state["violations"]) == start + 1  # the session would fail on this even though the test passed
    del g._state["violations"][start:]


# ---- processes --------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("command", [["docker", "ps"], ["docker.exe", "stop", "smtp-sink"], ["powershell", "-c", "x"],
                                     ["curl", "http://localhost:5678"], ["node", "-v"], ["cmd", "/c", "echo"],
                                     ["ssh", "host"], ["n8n", "start"], "docker start x"])
def test_service_and_unknown_programs_never_start(command):
    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        subprocess.run(command, capture_output=True, timeout=5)


def test_shell_commands_and_os_launchers_are_refused():
    with g.expect_violations():
        with pytest.raises(g.OfflineViolation):
            subprocess.run("echo hi", shell=True, capture_output=True)
        with pytest.raises(g.OfflineViolation):
            os.system("echo hi")
        with pytest.raises(g.OfflineViolation):
            os.popen("echo hi")
        with pytest.raises(g.OfflineViolation):
            webbrowser.open("http://localhost:5678")
        if hasattr(os, "startfile"):
            with pytest.raises(g.OfflineViolation):
                os.startfile(str(REPO))


def test_git_and_python_children_are_allowed_but_git_network_commands_are_not():
    assert subprocess.run(["git", "--version"], capture_output=True, text=True).returncode == 0
    assert subprocess.run([sys.executable, "-c", "print(41 + 1)"], capture_output=True, text=True).stdout.strip() == "42"
    for sub in ("push", "fetch", "pull", "clone", "ls-remote"):
        with g.expect_violations(), pytest.raises(g.OfflineViolation):
            subprocess.run(["git", sub], capture_output=True)
    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        subprocess.run(["git", "-C", ".", "fetch", "origin"], capture_output=True)


@pytest.mark.parametrize("flag", ["-I", "-E", "-S", "-IBs"])
def test_isolated_python_children_are_refused_because_they_would_skip_the_guard(flag):
    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        subprocess.run([sys.executable, flag, "-c", "print(1)"], capture_output=True)


def test_a_python_child_runs_under_the_same_guard():
    code = textwrap.dedent("""
        import socket
        try:
            socket.create_connection(("127.0.0.1", 5678), timeout=1)
            print("CONNECTED")
        except OSError as exc:
            print(type(exc).__name__)
    """)
    with g.expect_violations():
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30).stdout.strip()
    assert out == "OfflineViolation"
    assert g._state["expected"][-1]["child"] is True


# ---- environment and opt-in -------------------------------------------------------------------------------------------
def test_inherited_credentials_and_service_settings_are_withheld_by_name_only(monkeypatch):
    saved_withheld, saved_names = dict(g._state["withheld"]), list(g._state["scrubbed"])
    for name, value in {"N8N_API_KEY": "k-1", "MCP_N8N_API_KEY": "k-2", "N8N_BASE_URL": "http://localhost:5678",
                        "DOCKER_HOST": "tcp://x", "BREAKER_ALLOW_LIVE": "1", "BREAKER_S4_APPROVAL": "run:x",
                        "SOME_SERVICE_TOKEN": "t", "HARMLESS_SETTING": "keep"}.items():
        monkeypatch.setenv(name, value)
    try:
        names = g.scrub_environment()
        assert {"N8N_API_KEY", "MCP_N8N_API_KEY", "N8N_BASE_URL", "DOCKER_HOST", "BREAKER_ALLOW_LIVE", "BREAKER_S4_APPROVAL",
                "SOME_SERVICE_TOKEN"} <= set(names)
        assert "HARMLESS_SETTING" not in names and os.environ["HARMLESS_SETTING"] == "keep"
        assert all(n not in os.environ for n in ("N8N_API_KEY", "N8N_BASE_URL", "DOCKER_HOST", "BREAKER_ALLOW_LIVE"))
        assert "k-1" not in json.dumps(g._state["scrubbed"])  # names are reported, never values
    finally:
        os.environ.update({k: v for k, v in g._state["withheld"].items() if k not in saved_withheld})
        g._state["withheld"].update(saved_withheld)
        g._state["scrubbed"] = saved_names


def test_integration_is_off_and_the_environment_cannot_turn_it_on(monkeypatch):
    for name in ("BREAKER_INTEGRATION", "BREAKER_ALLOW_LIVE", "N8N_API_KEY", "N8N_BASE_URL", "INTEGRATION", "RUN_LIVE"):
        monkeypatch.setenv(name, "1")
    assert g.integration_enabled() is False


@pytest.mark.parametrize("args,expected", [
    (["git", "status"], None), (["git", "-C", "x", "log"], None), ([sys.executable, "-c", "1"], None),
    (["python", "-m", "pytest"], None), (["docker", "ps"], "process 'docker'"),
    (["git", "fetch"], "git fetch (network sub-command)"), ("whatever x", "process"), ([], "empty command")])
def test_command_policy_table(args, expected):
    reason = g._refuse_command(args, False)
    assert (reason is None) if expected is None else (reason is not None and expected in reason)


# ---- static classification ---------------------------------------------------------------------------------------------
def make_repo(tmp_path, body, policy_files):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text(body, encoding="utf-8")
    return {"schema_version": 1, "live_nodes": [], "reviewed_files": policy_files}


def test_a_file_that_can_reach_outside_the_process_must_have_a_reviewed_entry(tmp_path):
    policy = make_repo(tmp_path, "import subprocess\ndef test_a():\n    subprocess.run(['docker', 'ps'])\n", {})
    assert g.unclassified(tmp_path, policy) == ["tests/test_x.py"]
    policy["reviewed_files"]["tests/test_x.py"] = {"class": "OFFLINE_FAKE", "basis": "reviewed"}
    assert g.unclassified(tmp_path, policy) == []
    policy["reviewed_files"]["tests/test_x.py"] = {"class": "OFFLINE_FAKE", "basis": "  "}
    assert g.unclassified(tmp_path, policy) == ["tests/test_x.py"]
    policy["reviewed_files"]["tests/test_x.py"] = {"class": "TRUST_ME", "basis": "x"}
    assert g.unclassified(tmp_path, policy) == ["tests/test_x.py"]
    policy["reviewed_files"] = {"tests/test_*.py": {"class": "OFFLINE_FAKE", "basis": "glob"}}
    assert g.unclassified(tmp_path, policy) == []


def test_a_file_with_no_such_construct_needs_no_entry(tmp_path):
    policy = make_repo(tmp_path, "def test_a():\n    assert 1 + 1 == 2\n", {})
    assert g.unclassified(tmp_path, policy) == []


def test_a_malformed_policy_is_an_error_not_a_default(tmp_path):
    for bad in ("{}", '{"schema_version": 1}', "not json", '{"schema_version": 2, "live_nodes": [], "reviewed_files": {}}'):
        (tmp_path / "p.json").write_text(bad, encoding="utf-8")
        with pytest.raises((RuntimeError, ValueError)):
            g.load_policy(tmp_path, str(tmp_path / "p.json"))
    with pytest.raises(RuntimeError):
        g.load_policy(tmp_path / "nowhere")


def test_the_real_policy_covers_every_runtime_dependent_test_file_and_has_no_live_tests():
    policy = g.load_policy(REPO)
    assert g.unclassified(REPO, policy) == []
    assert policy["live_nodes"] == []  # the public suite is offline only


# ---- the plugin end to end, in fresh interpreters on throwaway projects ------------------------------------------------------
def project(tmp_path, files, policy_nodes=()):
    root = tmp_path / "proj"
    (root / "tests").mkdir(parents=True)
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (root / "policy.json").write_text(json.dumps({"schema_version": 1, "live_nodes": list(policy_nodes), "reviewed_files": {}}),
                                      encoding="utf-8")
    for name, body in files.items():
        (root / "tests" / name).write_text(textwrap.dedent(body), encoding="utf-8")
    return root


def run_project(root, *extra, env=None):
    report = root / "report.json"
    full_env = dict(os.environ, PYTHONPATH=str(REPO) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    full_env.update(env or {})
    full_env[g.CHILD_REPORT_ENV] = str(root / "children.jsonl")  # this inner session is judged on its own, not by ours
    proc = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tools.offline_guard", "-q",
                           "--breaker-offline-policy", str(root / "policy.json"), f"--breaker-guard-report={report}", *extra,
                           "tests"], cwd=root, capture_output=True, text=True, env=full_env, timeout=180)
    data = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else None
    return proc, data


def test_a_normal_offline_test_passes_and_the_guard_banner_is_shown(tmp_path):
    root = project(tmp_path, {"test_ok.py": "def test_ok():\n    assert 2 + 2 == 4\n"})
    proc, report = run_project(root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OFFLINE-GUARD: active mode=offline violations=0" in proc.stdout
    assert report["mode"] == "offline" and report["violations"] == []


@pytest.mark.parametrize("name,body", [
    ("loopback_n8n", "import socket\ndef test_x():\n    socket.create_connection(('127.0.0.1', 5678), timeout=1)\n"),
    ("swallowed", "import socket\ndef test_x():\n    try:\n        socket.create_connection(('127.0.0.1', 5678), timeout=1)\n    except Exception:\n        pass\n"),
    ("docker", "import subprocess\ndef test_x():\n    try:\n        subprocess.run(['docker', 'ps'])\n    except OSError:\n        pass\n"),
    ("notify", "import subprocess\ndef test_x():\n    subprocess.run(['powershell', '-Command', 'New-BurntToastNotification'])\n"),
    ("outside_http", "import urllib.request\ndef test_x():\n    urllib.request.urlopen('http://example.com', timeout=1)\n"),
])
def test_attempts_to_reach_services_fail_the_session_even_when_the_test_would_otherwise_pass(tmp_path, name, body):
    root = project(tmp_path, {f"test_{name}.py": body})
    proc, report = run_project(root)
    assert proc.returncode != 0, proc.stdout
    assert report["violations"] and "OFFLINE-GUARD: VIOLATION" in proc.stdout


def test_a_collection_time_side_effect_is_caught_not_just_test_bodies(tmp_path):
    root = project(tmp_path, {"test_import.py": "import socket\nsocket.create_connection(('127.0.0.1', 5678), timeout=1)\ndef test_x():\n    pass\n"})
    proc, report = run_project(root)
    assert proc.returncode != 0 and report["violations"]
    assert report["violations"][0]["test"] == "<collection/import>"


SENTINEL = """
    import os, pathlib, pytest
    @pytest.mark.integration
    def test_live():
        pathlib.Path("RAN_LIVE").write_text(os.environ.get("N8N_API_KEY", "absent"))
    def test_plain():
        pass
"""


def test_marked_integration_tests_never_run_offline_whatever_the_environment_holds(tmp_path):
    root = project(tmp_path, {"test_live.py": SENTINEL})
    proc, report = run_project(root, env={"N8N_API_KEY": "k", "N8N_BASE_URL": "http://localhost:5678",
                                          "BREAKER_ALLOW_LIVE": "1", "BREAKER_INTEGRATION": "1", "DOCKER_HOST": "x"})
    assert proc.returncode == 0, proc.stdout
    assert not (root / "RAN_LIVE").exists()
    assert any("test_live" in e["node"] for e in report["excluded"]) and "EXCLUDED" in proc.stdout
    assert {"N8N_API_KEY", "N8N_BASE_URL", "BREAKER_ALLOW_LIVE", "DOCKER_HOST"} <= set(report["env_names_withheld"])


def test_the_explicit_option_is_the_only_way_to_run_them(tmp_path):
    root = project(tmp_path, {"test_live.py": SENTINEL})
    proc, report = run_project(root, "--integration", env={"N8N_API_KEY": "k"})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (root / "RAN_LIVE").read_text() == "k"  # credentials come back only with the opt-in
    assert report["mode"] == "integration" and "mode=integration" in proc.stdout


def test_policy_listed_live_tests_are_excluded_before_they_run(tmp_path):
    body = ("import pathlib\ndef test_live_by_policy():\n    pathlib.Path('RAN_POLICY').write_text('x')\n"
            "def test_plain():\n    pass\n")
    root = project(tmp_path, {"test_p.py": body},
                   policy_nodes=[{"node": "tests/test_p.py::test_live_by_policy", "reason": "needs docker"}])
    proc, report = run_project(root)
    assert proc.returncode == 0 and not (root / "RAN_POLICY").exists()
    assert report["excluded"][0]["reason"] == "needs docker"


def test_a_missing_policy_stops_the_run_instead_of_defaulting(tmp_path):
    root = project(tmp_path, {"test_ok.py": "def test_ok():\n    pass\n"})
    (root / "policy.json").unlink()
    proc, _ = run_project(root)
    assert proc.returncode != 0


# ---- loopback receivers shared with child scripts -------------------------------------------------------------------------------------
def test_a_child_script_may_reach_a_receiver_its_parent_test_started_but_not_a_service_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    code = textwrap.dedent(f"""
        import socket
        for p in ({port}, 5678):
            try:
                socket.create_connection(("127.0.0.1", p), timeout=2).close()
                print(p, "connected")
            except OSError as exc:
                print(p, type(exc).__name__)
    """)
    with g.expect_violations():
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30).stdout.split("\n")
    server.close()
    assert f"{port} connected" in out and "5678 OfflineViolation" in out


def test_service_ports_stay_blocked_even_if_something_bound_them():
    g._state["ports"].add(5678)
    try:
        with g.expect_violations(), pytest.raises(g.OfflineViolation):
            socket.create_connection(("127.0.0.1", 5678), timeout=1)
    finally:
        g._state["ports"].discard(5678)


def test_connecting_to_the_closed_port_one_is_a_failure_test_not_a_violation():
    start = len(g._state["violations"])
    with pytest.raises(OSError) as raised:
        socket.create_connection(("127.0.0.1", 1), timeout=1)
    assert not isinstance(raised.value, g.OfflineViolation) and len(g._state["violations"]) == start


# ---- gaps found in review and closed: asyncio proactor connects, UDP, and opening Docker's pipe/socket -------------------------------------
def test_an_asyncio_connection_is_checked_too():
    import asyncio

    async def attempt():
        await asyncio.open_connection("127.0.0.1", 59999)  # a closed port nobody uses; refused before any packet is sent

    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        asyncio.run(attempt())


def test_udp_sends_to_outside_addresses_are_refused():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with g.expect_violations(), pytest.raises(g.OfflineViolation):
            sock.sendto(b"x", ("192.0.2.1", 9))
    finally:
        sock.close()


_BS = chr(92)
_PIPE = _BS * 2 + "." + _BS + "pipe" + _BS
@pytest.mark.parametrize("path", [_PIPE + "docker_engine", _PIPE + "any_service", "//./pipe/docker_engine",
                                  "/var/run/docker.sock"])
def test_opening_dockers_pipe_or_socket_path_is_refused_before_it_is_opened(path):
    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        open(path, "rb")
    with g.expect_violations(), pytest.raises(g.OfflineViolation):
        os.open(path, os.O_RDONLY)


def test_ordinary_files_still_open(tmp_path):
    target = tmp_path / "f.txt"
    target.write_text("ok", encoding="utf-8")
    assert open(target, encoding="utf-8").read() == "ok"
