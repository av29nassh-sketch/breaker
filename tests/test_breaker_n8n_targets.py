"""Target resolution: one approved local instance for both REST and MCP, with no fallback of any kind."""
from __future__ import annotations

import importlib.util
import pathlib
import socket
import sys
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


be = load("backend_for_targets", ROOT / "tools" / "breaker_n8n_backend.py")
BASE = "http://127.0.0.1:5678"


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("real network access attempted")
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)
    for name in ("N8N_BASE_URL", *be.MCP_ENDPOINT_ENV, be.ENV_APPROVAL):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("url, normalised", [
    ("http://127.0.0.1:5678", "http://127.0.0.1:5678"), ("http://localhost:5678/", "http://localhost:5678"),
    ("https://localhost", "https://localhost"), ("http://[::1]:5678", "http://[::1]:5678")])
def test_local_origins_are_accepted_and_normalised(url, normalised):
    assert be.approved_origin(url) == normalised == be.N8nBackend(expected_base_url=url, approval="").expected_base_url
    assert be.mcp_endpoint_for(url) == normalised + "/mcp-server/http"


@pytest.mark.parametrize("url", [
    "https://example-tunnel.ngrok-free.dev", "https://example.com", "http://192.168.1.20:5678",
    "http://0.0.0.0:5678", "http://localhost.evil.invalid:5678", "http://127.0.0.1.evil.invalid",
    "http://user:pw@127.0.0.1:5678", "http://127.0.0.1:5678/api", "http://127.0.0.1:5678?x=1", "http://127.0.0.1:5678#f",
    "ftp://127.0.0.1", "127.0.0.1:5678", "", "http://127.0.0.1:notaport"])
def test_non_local_or_ambiguous_targets_are_refused(url):
    with pytest.raises(be.BackendRefused):
        be.approved_origin(url)
    with pytest.raises(be.BackendRefused):
        be.N8nBackend(expected_base_url=url, approval="x")


def test_rest_environment_must_equal_the_approved_origin_after_normalisation(monkeypatch):
    monkeypatch.setenv(be.ENV_APPROVAL, "go")
    backend = be.N8nBackend(expected_base_url=BASE, approval="go")
    for bad in ("http://localhost:5678", "http://127.0.0.1:5679", "https://x.ngrok-free.dev", ""):
        monkeypatch.setenv("N8N_BASE_URL", bad)
        with pytest.raises((be.BackendRefused, be._lane.LaneError)):
            backend.check()
    monkeypatch.setenv("N8N_BASE_URL", BASE + "/")
    backend.check()


@pytest.mark.parametrize("name", be.MCP_ENDPOINT_ENV)
def test_an_mcp_endpoint_override_pointing_elsewhere_is_refused(monkeypatch, name):
    monkeypatch.setenv(name, "https://example-tunnel.ngrok-free.dev/mcp-server/http")
    with pytest.raises(be.BackendRefused):
        be.check_endpoint_environment(BASE)
    monkeypatch.setenv(name, BASE + "/mcp-server/http/")
    be.check_endpoint_environment(BASE)


def test_make_transport_refuses_ambiguity_and_builds_only_the_explicit_endpoint(monkeypatch):
    monkeypatch.setenv(be.ENV_APPROVAL, "go")
    monkeypatch.setenv("N8N_BASE_URL", BASE)
    monkeypatch.setenv("MCP_N8N_API_KEY", "synthetic-not-a-key")
    backend = be.N8nBackend(expected_base_url=BASE, approval="go")
    monkeypatch.setenv("N8N_MCP_ENDPOINT", "http://127.0.0.1:9999/mcp-server/http")
    with pytest.raises(be.BackendRefused):
        be.make_transport(backend)
    monkeypatch.delenv("N8N_MCP_ENDPOINT")
    guarded = be.make_transport(backend)
    assert guarded._transport.endpoint == BASE + "/mcp-server/http"


def test_guarded_transport_requires_the_exact_endpoint_and_exposes_only_read_only_discovery(monkeypatch):
    monkeypatch.setenv(be.ENV_APPROVAL, "go")
    monkeypatch.setenv("N8N_BASE_URL", BASE)
    backend = be.N8nBackend(expected_base_url=BASE, approval="go")

    class Inner:
        def __init__(self, endpoint):
            self.endpoint, self.calls = endpoint, []

        def initialize(self):
            self.calls.append("initialize")
            return {"serverInfo": {"name": "synthetic", "version": "0"}, "protocolVersion": "x"}

        def list_tools(self):
            self.calls.append("list_tools")
            return [{"name": "test_workflow"}, {"name": "get_workflow_execution"}]

    for wrong in (BASE, BASE + "/mcp-server/http/extra", "http://127.0.0.1:5679/mcp-server/http",
                  BASE + "/mcp-server/http?x=1"):
        with pytest.raises(be.BackendRefused):
            be.GuardedTransport(Inner(wrong), backend)
    inner = Inner(BASE + "/mcp-server/http")
    info = be.GuardedTransport(inner, backend).preflight()
    assert info["tools"] == ["get_workflow_execution", "test_workflow"] and inner.calls == ["initialize", "list_tools"]
    disarmed = be.N8nBackend(expected_base_url=BASE, approval="")
    with pytest.raises(be.BackendDisarmed):
        be.GuardedTransport(Inner(BASE + "/mcp-server/http"), disarmed).preflight()
