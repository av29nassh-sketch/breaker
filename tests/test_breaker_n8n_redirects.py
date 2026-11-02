"""A redirect must never be followed: it would carry the API key or token to a host nobody approved.

No socket is opened. A fake HTTP handler stands in for the network and records every request it is asked to make.
"""
from __future__ import annotations

import email.message
import importlib.util
import io
import json
import pathlib
import socket
import sys
import urllib.error
import urllib.request
import urllib.response

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = "http://127.0.0.1:5678"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


be = load("backend_for_redirects", ROOT / "tools" / "breaker_n8n_backend.py")


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("real network access attempted")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setenv("N8N_BASE_URL", BASE)
    monkeypatch.setenv("N8N_API_KEY", "synthetic-not-a-key")
    monkeypatch.setenv(be.ENV_APPROVAL, "armed")
    for name in be.MCP_ENDPOINT_ENV:
        monkeypatch.delenv(name, raising=False)
    yield
    urllib.request.install_opener(None)


class FakeHTTP(urllib.request.HTTPHandler):
    """Answers every request with a configured status; a redirect names a host that must never be contacted."""

    def __init__(self, code=302, body=b"", location="http://attacker.invalid/steal"):
        super().__init__()
        self.requests, self.code, self.body, self.location = [], code, body, location

    def http_open(self, req):
        self.requests.append((req.full_url, req.get_header("X-n8n-api-key")))
        headers = email.message.Message()
        headers["Content-Type"] = "application/json"
        if 300 <= self.code < 400:
            headers["Location"] = self.location
        response = urllib.response.addinfourl(io.BytesIO(self.body), headers, req.full_url, self.code)
        response.msg = "synthetic"
        return response


def test_the_redirect_handler_never_builds_a_follow_up_request():
    handler = be._NoRedirect()
    request = urllib.request.Request(BASE + "/x")
    assert handler.redirect_request(request, None, 302, "Found", {}, "http://attacker.invalid/") is None


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_an_http_redirect_is_not_followed_and_the_key_goes_nowhere_else(code):
    fake = FakeHTTP(code=code)
    opener = be.make_opener(fake)
    with pytest.raises(urllib.error.HTTPError) as error:
        opener.open(urllib.request.Request(BASE + "/api/v1/workflows"))
    assert error.value.code == code
    assert [url for url, _ in fake.requests] == [BASE + "/api/v1/workflows"]  # the Location target was never requested


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_rest_helper_refuses_a_redirect(monkeypatch, code):
    fake = FakeHTTP(code=code)
    monkeypatch.setattr(be, "_OPENER", be.make_opener(fake))
    with pytest.raises(be.BackendRefused, match="redirect"):
        be._api("GET", "/api/v1/workflows?limit=1")
    assert [url for url, _ in fake.requests] == [BASE + "/api/v1/workflows?limit=1"]


def test_rest_helper_still_returns_normal_answers_and_errors(monkeypatch):
    for code, body, expected in ((200, b'{"data": []}', (200, {"data": []})), (200, b"", (200, None))):
        fake = FakeHTTP(code=code, body=body)
        monkeypatch.setattr(be, "_OPENER", be.make_opener(fake))
        assert be._api("GET", "/api/v1/workflows") == expected
        assert fake.requests[0][1] == "synthetic-not-a-key"  # the key is sent only to the approved origin
    fake = FakeHTTP(code=404, body=b"not found")
    monkeypatch.setattr(be, "_OPENER", be.make_opener(fake))
    assert be._api("GET", "/api/v1/workflows/missing") == (404, "not found")


def test_the_lane_copy_used_by_the_backend_goes_through_the_no_redirect_helper():
    assert be._lane.api is be._api


def test_backend_operations_stop_on_a_redirect_and_contact_no_other_host(monkeypatch):
    fake = FakeHTTP(code=302)
    monkeypatch.setattr(be, "_OPENER", be.make_opener(fake))
    backend = be.N8nBackend(expected_base_url=BASE, approval="armed", protected_ids=("P1",))
    with pytest.raises(be.BackendRefused, match="redirect"):
        backend.snapshot()
    with pytest.raises(be.BackendRefused, match="redirect"):
        backend.create({"name": "[BREAKER PROBE] x", "nodes": [], "connections": {}, "settings": {}})
    assert backend.created == {} and all(url.startswith(BASE) for url, _ in fake.requests) and len(fake.requests) == 2


def test_the_process_wide_opener_used_by_the_mcp_transport_refuses_redirects():
    be.install_no_redirects()
    opener = urllib.request._opener
    assert any(isinstance(h, be._NoRedirect) for h in opener.handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in opener.handlers)


def test_make_transport_installs_the_no_redirect_opener(monkeypatch):
    backend = be.N8nBackend(expected_base_url=BASE, approval="armed")
    monkeypatch.setenv("MCP_N8N_API_KEY", "synthetic-not-a-token")
    urllib.request.install_opener(None)
    guarded = be.make_transport(backend)
    assert any(isinstance(h, be._NoRedirect) for h in urllib.request._opener.handlers)
    assert guarded._transport.endpoint == BASE + "/mcp-server/http"


def test_the_policy_gate_still_holds_for_the_backend_module():
    source = (ROOT / "tools" / "breaker_n8n_backend.py").read_text(encoding="utf-8").lower()
    for token in ("ngrok", "mcp_call_tool", "urlopen", '"put"', '"patch"', "/activate"):
        assert token not in source, token
