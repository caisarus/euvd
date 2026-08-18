"""Executable "must never happen" list for INV-8 (test_plan.md §6).

INV-8 is the project's central promise: *nothing is ever submitted or filed
automatically — no code path calls a submission endpoint*. It was deferred when the
invariant list was written ("planned M5, when webhooks add POST"); M5 shipped the
webhook sink, so the promise is now enforceable and enforced here.

The guarantee is structural rather than behavioural, so these are AST tests over the
package source (test_plan.md §6 specifies "AST/grep test: no outbound POST targets
outside webhook sink allowlist"). Four independent walls, each of which alone would
stop an accidental filing:

1. only two HTTP verbs reach the transport at all, from two named methods;
2. nothing bypasses `ApiClient` by calling a verb on an HTTP client directly;
3. the one POST-capable method is called from exactly one place — the webhook sink;
4. the CRA module, which drafts the notifications, contains no endpoint to send to,
   and no submission target can be introduced through configuration.

A new outbound POST is not forbidden by these tests — it is forbidden *silently*. Any
new call site, verb, or endpoint fails an exact-set assertion and has to be argued for
in review.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = pytest.mark.invariant

REPO_SRC = Path(__file__).resolve().parents[2] / "src" / "euvd_watch"

# The only outbound destinations the tool may know about: three read-only data sources.
# A submission endpoint appearing here would mean euvd-watch could file on its own.
READ_ONLY_DATA_SOURCES = {
    "https://euvdservices.enisa.europa.eu/api",
    "https://api.first.org/data/v1/epss",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}

# Verb-named methods on an HTTP client. `ApiClient._request_with_retries` is the one
# sanctioned caller and it goes through `.request(method, ...)`, so any of these
# appearing on a client receiver means something reached the network around it.
CLIENT_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "send", "stream"})

# Receivers that are HTTP clients: the httpx module itself, and anything named like a
# client — `self._client` (ApiClient's own), but also a reach-around such as
# `self._api._client`, which is how a bypass would most plausibly be spelled.
# Deliberately NOT matched: `app`/`router`, whose `.post` is FastAPI's *inbound* route
# decorator — accepting a human's form submission is the opposite of the tool filing
# something itself.
CLIENT_MODULES = frozenset({"httpx", "requests"})


def _is_client_receiver(receiver: str | None) -> bool:
    """True for anything that looks like an HTTP client object or module."""
    if receiver is None:
        return False
    return (
        receiver in CLIENT_MODULES
        or receiver == "client"
        or receiver.endswith("_client")
        or receiver.endswith(".client")
    )


@dataclass(frozen=True)
class _Site:
    """One call, with the class and function it sits in."""

    name: str
    receiver: str | None
    cls: str | None
    func: str | None
    node: ast.Call


class _CallCollector(ast.NodeVisitor):
    """Collects every call in a module together with its enclosing class/function."""

    def __init__(self) -> None:
        self.calls: list[_Site] = []
        self._cls: str | None = None
        self._func: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        outer, self._cls = self._cls, node.name
        self.generic_visit(node)
        self._cls = outer

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        outer, self._func = self._func, node.name
        self.generic_visit(node)
        self._func = outer

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        outer, self._func = self._func, node.name
        self.generic_visit(node)
        self._func = outer

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute):
            self.calls.append(_Site(func.attr, _receiver(func.value), self._cls, self._func, node))
        elif isinstance(func, ast.Name):
            self.calls.append(_Site(func.id, None, self._cls, self._func, node))
        self.generic_visit(node)


def _receiver(node: ast.expr) -> str | None:
    """Source-level spelling of a call's receiver: `self._client`, `httpx`, `app`…"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        inner = _receiver(node.value)
        return f"{inner}.{node.attr}" if inner else None
    return None


def _modules() -> list[Path]:
    return sorted(p for p in REPO_SRC.rglob("*.py") if "__pycache__" not in p.parts)


def _rel(path: Path) -> str:
    return path.relative_to(REPO_SRC).as_posix()


def _calls(path: Path) -> list[_Site]:
    collector = _CallCollector()
    collector.visit(ast.parse(path.read_text(encoding="utf-8")))
    return collector.calls


def _string_constants(path: Path) -> list[str]:
    return [
        node.value
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def test_inv8_only_get_and_post_reach_the_transport() -> None:
    """Exactly two verbs, from exactly two methods — and POST only from `post_json`.

    `_request_with_retries` takes the verb as a parameter, so this pins which methods
    may pass which verb. A non-literal verb collapses to None and fails the same way.
    """
    sites = [s for s in _calls(REPO_SRC / "http.py") if s.name == "_request_with_retries"]
    verbs = {
        (
            s.func,
            s.node.args[0].value
            if s.node.args and isinstance(s.node.args[0], ast.Constant)
            else None,
        )
        for s in sites
    }
    assert verbs == {("get_json", "GET"), ("post_json", "POST")}, (
        f"the set of (method, HTTP verb) pairs reaching the transport changed: {verbs}"
    )


def test_inv8_nothing_calls_a_verb_on_an_http_client_directly() -> None:
    """No `self._client.post(...)` / `httpx.post(...)` anywhere — everything goes
    through `_request_with_retries`, whose verbs the test above pins."""
    offenders = [
        f"{_rel(path)}:{site.func}: {site.receiver}.{site.name}"
        for path in _modules()
        for site in _calls(path)
        if site.name in CLIENT_VERBS and _is_client_receiver(site.receiver)
    ]
    assert offenders == [], f"HTTP verb called directly on a client: {offenders}"


def test_inv8_post_json_is_called_only_by_the_webhook_sink() -> None:
    """The allowlist, spelled out: one module, one class.

    `post_json` is the only method that can send data anywhere. Its callers are an
    exact set, so a second one — a CRA "submit" helper, a new sink — fails here.
    """
    callers = {
        (_rel(path), site.cls)
        for path in _modules()
        for site in _calls(path)
        if site.name == "post_json"
    }
    assert callers == {("watch/sinks.py", "WebhookSink")}, (
        f"post_json call sites outside the webhook sink allowlist: {callers}"
    )


def test_inv8_the_cra_module_has_no_endpoint_to_submit_to() -> None:
    """The code that drafts Article 14 notifications knows no URL at all.

    This is the human-in-the-loop guarantee made structural: even a bug cannot file a
    notification from a module that holds no address to file it to.
    """
    offenders = [
        f"{_rel(path)}: {value!r}"
        for path in sorted((REPO_SRC / "cra").rglob("*.py"))
        for value in _string_constants(path)
        if "://" in value
    ]
    assert offenders == [], f"the CRA module gained a network endpoint: {offenders}"


def test_inv8_no_submission_endpoint_can_be_configured() -> None:
    """Config may name read-only data sources and nothing else.

    A POST target reachable from a config file or environment variable would let a
    deployment turn on automatic filing without touching the code; the webhook URL is
    deliberately a `--webhook` flag only, passed per run.
    """
    configured = {value for value in _string_constants(REPO_SRC / "config.py") if "://" in value}
    assert configured == READ_ONLY_DATA_SOURCES, (
        f"configurable endpoints changed: {configured ^ READ_ONLY_DATA_SOURCES}"
    )
