"""The n8n APPLICATION version is read and checked on its own; the MCP server identity is never taken as proof of it."""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import sys
import urllib.error

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5678"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


front = load("front_appver_under_test", ROOT / "tools" / "breaker_verify_workflow.py")
be = front.be


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """Records every request; answers with a canned body or raises, so nothing touches a socket."""

    def __init__(self, body=None, error=None):
        self.body, self.error, self.requests = body, error, []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if self.error:
            raise self.error
        return Response(json.dumps(self.body).encode("utf-8") if not isinstance(self.body, bytes) else self.body)


def test_reads_versionCli_from_the_settings_data_block_with_one_get_and_no_api_key():
    opener = FakeOpener({"data": {"versionCli": "2.35.4", "other": 1}})
    assert be.read_application_version(BASE, opener) == "2.35.4"
    (request,) = opener.requests
    assert request.get_method() == "GET" and request.full_url == BASE + "/rest/settings"
    assert not any(h.lower() in ("x-n8n-api-key", "authorization") for h in request.headers)


@pytest.mark.parametrize("body", [{"data": {}}, {"data": {"versionCli": ""}}, {"data": {"versionCli": 2}}, [], {"x": 1}, b"not json"])
def test_a_response_without_a_usable_versionCli_is_refused(body):
    with pytest.raises(be.BackendRefused, match="unreadable"):
        be.read_application_version(BASE, FakeOpener(body))


@pytest.mark.parametrize("code", [302, 401, 404, 500])
def test_http_errors_and_redirects_are_refused(code):
    err = urllib.error.HTTPError(BASE + "/rest/settings", code, "x", {}, io.BytesIO(b""))
    with pytest.raises(be.BackendRefused, match=str(code)):
        be.read_application_version(BASE, FakeOpener(error=err))


def test_an_unreachable_server_is_refused_not_guessed():
    with pytest.raises(be.BackendRefused, match="unreadable"):
        be.read_application_version(BASE, FakeOpener(error=urllib.error.URLError("refused")))


@pytest.mark.parametrize("url", ["http://example.com", "http://10.0.0.5:5678", "http://127.0.0.1:5678/api", "http://u:p@127.0.0.1:5678"])
def test_only_the_approved_loopback_origin_is_ever_read(url):
    opener = FakeOpener({"data": {"versionCli": "2.35.4"}})
    with pytest.raises(be.BackendRefused):
        be.read_application_version(url, opener)
    assert opener.requests == []


def test_check_requires_the_flag_and_compares_exactly(monkeypatch):
    monkeypatch.setattr(be, "read_application_version", lambda base_url, opener=None: "2.35.4")
    for missing in (None, "", "  "):
        with pytest.raises(front.cli.OperatorError, match="--expect-n8n-version"):
            front.check_application_version(BASE, missing)
    for wrong in ("2.35.3", "2.35", "2.35.4-beta", "v2.35.4"):
        with pytest.raises(front.cli.OperatorError, match="nothing was created"):
            front.check_application_version(BASE, wrong)
    got = front.check_application_version(BASE, " 2.35.4 ")
    assert got["application_version"] == "2.35.4" and "operator-asserted" in got["application_version_basis"]


def test_a_flag_is_not_enough_when_the_live_read_fails(monkeypatch):
    def unreadable(base_url, opener=None):
        raise be.BackendRefused("application version unreadable: URLError")
    monkeypatch.setattr(be, "read_application_version", unreadable)
    with pytest.raises(be.BackendRefused, match="unreadable"):
        front.check_application_version(BASE, "2.35.4")


def test_the_mcp_check_does_not_vouch_for_the_application():
    class T:
        def preflight(self):
            return {"serverInfo": {"name": "n8n MCP Server", "version": "1.1.0"}, "tools": list(be.TRANSPORT_OPERATIONS)}
    rec = {"server_info": {"name": "n8n MCP Server", "version": "1.1.0"}}
    got = front.check_instance_identity(T(), [("mechanism record", rec)])
    assert "application_version" not in got
    assert "nothing about the n8n application build" in got["mcp_scope"]


# ---- instances that do not expose the version: container-image evidence may stand in, labelled as such -------------------
OBSERVED = {"data": {"settingsMode": "public", "userManagement": {"authenticationMethod": "email"}}}  # what the real instance answered
LINE = "docker.n8n.io/n8nio/n8n:2.35.4  sha256:" + "ab" * 32 + "  2026-10-22T07:40:56.972450461Z"


def not_exposed(base_url, opener=None):
    raise be.VersionNotExposed("application version unreadable: the settings response has no versionCli")


def test_the_public_settings_block_is_recognised_as_n8n_without_a_version():
    with pytest.raises(be.VersionNotExposed):
        be.read_application_version(BASE, FakeOpener(OBSERVED))
    for other in ({"data": {}}, {"data": {"foo": 1}}, {"hello": "world"}):  # not recognisably n8n: plain refusal, no fallback
        with pytest.raises(be.BackendRefused) as caught:
            be.read_application_version(BASE, FakeOpener(other))
        assert not isinstance(caught.value, be.VersionNotExposed)


def test_image_evidence_parses_the_docker_inspect_line():
    got = front.parse_image_evidence(LINE, "2.35.4")
    assert got == {"image_tag": "docker.n8n.io/n8nio/n8n:2.35.4", "image_id": "sha256:" + "ab" * 32,
                   "container_started_at": "2026-10-22T07:40:56.972450461Z"}
    assert front.parse_image_evidence(" ".join(LINE.split()[:2]), "2.35.4")["container_started_at"] is None


@pytest.mark.parametrize("line", ["", "docker.n8n.io/n8nio/n8n:latest sha256:" + "ab" * 32, "docker.n8n.io/n8nio/n8n:2.35.3 sha256:" + "ab" * 32,
                                  "n8n 2.35.4 sha256:" + "ab" * 32, "docker.n8n.io/n8nio/n8n:2.35.4 sha256:abc",
                                  "docker.n8n.io/n8nio/n8n:2.35.4 " + "ab" * 32, "host:5000/n8n sha256:" + "ab" * 32,
                                  "docker.n8n.io/n8nio/n8n:2.35.4 sha256:" + "ab" * 32 + " a b"])
def test_image_evidence_that_does_not_support_the_version_is_refused(line):
    with pytest.raises(front.cli.OperatorError):
        front.parse_image_evidence(line, "2.35.4")


def test_fallback_is_used_only_when_the_version_is_not_exposed_and_is_labelled(monkeypatch):
    monkeypatch.setattr(be, "read_application_version", not_exposed)
    got = front.check_application_version(BASE, "2.35.4", LINE)
    assert got["application_version"] is None and got["application_version_confirmed_live"] is False
    assert "did not verify" in got["application_version_basis"] and got["container_image_evidence"]["image_tag"].endswith(":2.35.4")
    with pytest.raises(be.VersionNotExposed):  # no evidence, no run
        front.check_application_version(BASE, "2.35.4", None)
    with pytest.raises(front.cli.OperatorError):  # evidence for another version does not help
        front.check_application_version(BASE, "2.35.4", LINE.replace(":2.35.4", ":2.35.3"))


def test_evidence_never_overrides_a_live_read_or_an_unreachable_instance(monkeypatch):
    monkeypatch.setattr(be, "read_application_version", lambda base_url, opener=None: "2.36.0")
    with pytest.raises(front.cli.OperatorError, match="not the expected"):
        front.check_application_version(BASE, "2.35.4", LINE)

    def unreachable(base_url, opener=None):
        raise be.BackendRefused("application version unreadable: URLError")
    monkeypatch.setattr(be, "read_application_version", unreachable)
    with pytest.raises(be.BackendRefused):
        front.check_application_version(BASE, "2.35.4", LINE)
    monkeypatch.setattr(be, "read_application_version", lambda base_url, opener=None: "2.35.4")
    got = front.check_application_version(BASE, "2.35.4", LINE)  # a live read wins and is not downgraded
    assert got["application_version"] == "2.35.4" and got["application_version_confirmed_live"] is True and "container_image_evidence" not in got


# ---- a refusal leaves a stopped-report, and never in a folder it did not create --------------------------------------------
FX = ROOT / "fixtures" / "requirements" / "lead-intake"


def run_main(tmp_path, label, monkeypatch, capsys):
    def refuse(args, run_dir, report, context):
        raise be.BackendRefused("application version unreadable: test")
    monkeypatch.setattr(front, "real_wiring", refuse)
    argv = [str(FX / "workflow.json"), "--cases", str(FX / "cases.json"), "--out-root", str(tmp_path / "scratch"), "--label", label,
            "--run", "--base-url", BASE, "--mechanism-record", "x.json"]
    code = front.main(argv)
    capsys.readouterr()
    return code


def test_a_refused_run_writes_a_stopped_report_that_is_not_a_verdict(tmp_path, monkeypatch, capsys):
    assert run_main(tmp_path, "s1", monkeypatch, capsys) == 2
    stopped = json.loads((tmp_path / "scratch" / "s1" / "stopped.json").read_text(encoding="utf-8"))
    assert stopped["stopped"] is True and stopped["verdict"] is None and stopped["created_journal_present"] is False
    assert stopped["error_type"] == "BackendRefused" and "application version unreadable" in stopped["message"]


def test_a_reused_label_never_touches_the_existing_evidence_folder(tmp_path, monkeypatch, capsys):
    existing = tmp_path / "scratch" / "s2"
    existing.mkdir(parents=True)
    (existing / "keep.txt").write_text("evidence", encoding="utf-8")
    assert run_main(tmp_path, "s2", monkeypatch, capsys) == 2
    assert sorted(p.name for p in existing.iterdir()) == ["keep.txt"]
