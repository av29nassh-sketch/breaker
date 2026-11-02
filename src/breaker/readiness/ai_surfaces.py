"""Generic AI-surface detection for AI calls implemented through generic HTTP Request nodes.

WHAT WAS BROKEN
---------------
Breaker's only structural AI-surface reader was ``profile.classify_node_type``, which decides from the *node
type* alone. ``n8n-nodes-base.httpRequest`` maps to ``{"dependency": True}`` and never to ``{"ai": True}``, so a
model call implemented as an HTTP Request (the shape sample-workflow-v1.1.0 uses) exposed no AI surface at
all: ``HAS_AI_COMPONENT`` settled to ``False`` and every AI row was marked
``NOT_APPLICABLE / WORKFLOW_HAS_NO_AI_COMPONENT`` on a workflow that plainly calls a model. That is a Breaker
detection gap, not a candidate property.

WHAT THIS MODULE DOES
---------------------
It claims an AI surface from an HTTP Request node **only** when grounded, structural evidence supports it, and
it records HOW and WHY for every claim. It is data-driven: the provider rules and the known-non-AI destination
patterns are registry data, and the Command Code entries are read out of Breaker's own provider metadata
(:class:`breaker.semantic.providers.ProviderConfig`) rather than hard-coded per candidate.

Evidence, strongest first:

* **provider registry endpoint match** — the request URL matches a registered AI-provider endpoint pattern;
* **model field** — the request's JSON body declares a top-level ``model`` / ``model_id`` / ``deployment`` key;
* **AI request shape** — the body declares an AI-shaped field (``messages``, ``questions``, ``prompt``, ...);
* **provider credential** — the node references a credential type/name the registry associates with a provider.
  A credential is *weak* evidence: on its own it is never enough, and a contradicting request shape makes the
  node NOT_AI rather than AI.

A verdict is one of:

* ``AI`` — grounded evidence supports an AI call; the node is added to ``profile.ai_surfaces``;
* ``NOT_AI`` — positive evidence says the call is not an AI call (a known non-AI destination, or a provider
  credential whose request shape contradicts AI use);
* ``UNRESOLVED`` — nothing settles it (an ambiguous endpoint, a bare model-like string, partial evidence). The
  node is left out of ``ai_surfaces`` and recorded as an unknown, never guessed into either bucket.

Nothing here reads a credential value, executes anything or writes to a frozen artifact.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

# ------------------------------------------------------------------------------------------ request shape

#: Top-level request-body keys that name a model. A ``model`` *field* in a structured request is structural
#: evidence; a bare model-like string somewhere in the node is not.
MODEL_FIELDS: frozenset[str] = frozenset({"model", "model_id", "modelid", "deployment", "deployment_id",
                                          "engine", "model_name"})

#: Top-level request-body keys that only make sense for a model/AI request. Presence of one of these *and* a
#: model field is a structured AI request contract.
AI_SHAPE_FIELDS: frozenset[str] = frozenset({
    "messages", "prompt", "prompts", "questions", "system", "instructions", "response_format", "temperature",
    "max_tokens", "max_output_tokens", "top_p", "top_k", "stream", "tools", "tool_choice", "choices", "n",
    "stop", "frequency_penalty", "presence_penalty", "input", "logprobs", "best_of", "seed",
})

#: HTTP methods on which a body is expected. A body-less GET is a shape that contradicts AI *use*.
WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})


# ------------------------------------------------------------------------------------------ the registry

@dataclass(frozen=True)
class ProviderRule:
    """One AI provider as registry data: the endpoints, model ids and credentials that identify it."""

    provider: str
    endpoint_patterns: tuple[str, ...] = ()
    model_patterns: tuple[str, ...] = ()
    credential_types: tuple[str, ...] = ()
    credential_names: tuple[str, ...] = ()
    note: str = ""

    def endpoint_match(self, url: str) -> str:
        """The first endpoint pattern that matches, or ``""``."""
        lowered = (url or "").lower()
        for pattern in self.endpoint_patterns:
            if pattern and pattern.lower() in lowered:
                return pattern
        return ""

    def model_match(self, model_id: str) -> str:
        """The first model-id pattern that matches a literal model value, or ``""``."""
        lowered = (model_id or "").lower()
        for pattern in self.model_patterns:
            if pattern and pattern.lower() in lowered:
                return pattern
        return ""

    def credential_match(self, credential_types: Iterable[str], credential_names: Iterable[str]) -> str:
        """The credential type/name that matches, or ``""``. Names are matched case-insensitively."""
        types = {str(item).strip().lower() for item in credential_types}
        names = [str(item).strip().lower() for item in credential_names]
        for candidate in self.credential_types:
            if candidate.lower() in types:
                return f"type:{candidate}"
        for candidate in self.credential_names:
            needle = candidate.lower()
            for name in names:
                if needle and needle in name:
                    return f"name:{candidate}"
        return ""


def _commandcode_rule() -> ProviderRule | None:
    """Derive the Command Code rule from Breaker's own provider metadata (endpoints and model ids).

    Deferred import: the readiness layer must not hard-depend on the semantic layer, and the values are
    Breaker's own configured endpoints, not a candidate-specific literal.
    """
    try:
        from breaker.semantic.providers import ProviderConfig
    except Exception:  # pragma: no cover - the semantic layer is optional for a static readiness run
        return None
    config = ProviderConfig.default()
    endpoints: list[str] = []
    models: list[str] = []
    for spec in (config.decision, config.reasoning):
        url = str(spec.endpoint or "")
        if url:
            parsed = re.sub(r"^https?://", "", url).rstrip("/")
            endpoints.append(parsed)
        if spec.model_id:
            models.append(str(spec.model_id))
    if not endpoints and not models:
        return None
    return ProviderRule(
        provider="commandcode",
        endpoint_patterns=tuple(dict.fromkeys(endpoints)),
        model_patterns=tuple(dict.fromkeys(models)),
        credential_types=("httpHeaderAuth", "openAiApi", "httpBearerAuth"),
        credential_names=("Command Code API",),
        note="derived from Breaker's own ProviderConfig provider metadata",
    )


def _builtin_rules() -> tuple[ProviderRule, ...]:
    """The provider registry: well-known AI providers plus Breaker's own configured provider metadata."""
    rules: list[ProviderRule] = []
    commandcode = _commandcode_rule()
    if commandcode is not None:
        rules.append(commandcode)
    rules.extend((
        ProviderRule("openai", ("api.openai.com/",), ("gpt-", "o1", "o3", "o4", "davinci", "text-embedding"),
                     ("openAiApi",), ("OpenAI",)),
        ProviderRule("anthropic", ("api.anthropic.com/",), ("claude",), ("anthropicApi",), ("Anthropic",)),
        ProviderRule("azure-openai", (".openai.azure.com/", "openai.azure.com/"), ("gpt-", "deployment"),
                     ("azureOpenAiApi",), ("Azure OpenAI",)),
        ProviderRule("google-ai", ("generativelanguage.googleapis.com/", "aiplatform.googleapis.com/"),
                     ("gemini", "palm", "bison"), ("googlePalmApi", "googleAiApi"), ("Google",)),
        ProviderRule("mistral", ("api.mistral.ai/",), ("mistral", "mixtral", "codestral"), ("mistralApi",),
                     ("Mistral",)),
        ProviderRule("cohere", ("api.cohere.ai/",), ("command-", "embed-"), ("cohereApi",), ("Cohere",)),
        ProviderRule("groq", ("api.groq.com/",), ("llama", "mixtral", "gemma"), ("groqApi",), ("Groq",)),
        ProviderRule("ollama", ("localhost:11434/", "127.0.0.1:11434/", "/api/generate", "/api/chat"),
                     (), ("ollamaApi",), ("Ollama",)),
        ProviderRule("deepseek", ("api.deepseek.com/",), ("deepseek",), ("deepSeekApi",), ("DeepSeek",)),
    ))
    return tuple(rules)


#: The data-driven provider registry. Exposed so a report can quote it instead of paraphrasing.
PROVIDER_RULES: tuple[ProviderRule, ...] = _builtin_rules()

#: Destinations that are known *not* to be AI providers, as registry data. A request to one of these is NOT_AI
#: (a database RPC, a REST data service), which is what keeps an ordinary persistence call from being read as
#: either an AI surface or an "ambiguous" unknown.
NON_AI_ENDPOINT_PATTERNS: tuple[tuple[str, str], ...] = (
    (".supabase.co/rest/v1/rpc/", "supabase database RPC"),
    (".supabase.co/rest/v1/", "supabase REST data service"),
    (".supabase.co/", "supabase project endpoint"),
    (".airtable.com/", "airtable REST data service"),
    ("criteria records.googleapis.com/", "google criteria records data service"),
    ("api.stripe.com/", "stripe payment API"),
    ("api.sendgrid.com/", "sendgrid delivery API"),
    ("quickbooks.api.intuit.com/", "quickbooks accounting API"),
    ("api.xero.com/", "xero accounting API"),
)


def non_ai_match(url: str) -> str:
    """The known-non-AI destination a URL matches, or ``""``."""
    lowered = (url or "").lower()
    for pattern, why in NON_AI_ENDPOINT_PATTERNS:
        if pattern in lowered:
            return f"{pattern} ({why})"
    return ""


# ------------------------------------------------------------------------------------- body reinterpretation

def _strip_expression_wrapper(text: str) -> str:
    """Peel the n8n expression wrappers (``=``, ``{{ }}``, ``( )``) down to the value expression.

    The wrapper is what n8n writes around a field expression; ``={{ ({ model: 'x' }) }}`` is the object
    ``{ model: 'x' }``. Wrappers are peeled only when they balance, so a real parenthesis inside the expression
    is never mistaken for a wrapper.
    """
    body = (text or "").strip()
    if body.startswith("="):
        body = body[1:].strip()
    changed = True
    while changed:
        changed = False
        if len(body) >= 4 and body.startswith("{{") and body.endswith("}}"):
            body = body[2:-2].strip()
            changed = True
            continue
        if body.startswith("(") and body.endswith(")") and _matching_close(body, 0, "(", ")") == len(body) - 1:
            body = body[1:-1].strip()
            changed = True
    return body


def _matching_close(text: str, start: int, opener: str, closer: str) -> int:
    """Index of the ``closer`` that matches the ``opener`` at ``start``, ignoring string literals."""
    depth = 0
    index = start
    length = len(text)
    while index < length:
        char = text[index]
        if char in "'\"`":
            index = _skip_string(text, index)
            continue
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _skip_string(text: str, start: int) -> int:
    quote = text[start]
    index = start + 1
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == quote:
            return index + 1
        index += 1
    return index


def _split_top_level(inner: str) -> list[str]:
    """Split an object literal's inner text on commas that sit at depth 0."""
    parts: list[str] = []
    depth = 0
    start = 0
    index = 0
    length = len(inner)
    while index < length:
        char = inner[index]
        if char in "'\"`":
            index = _skip_string(inner, index)
            continue
        if char in "{([":
            depth += 1
        elif char in "})]":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(inner[start:index])
            start = index + 1
        index += 1
    parts.append(inner[start:])
    return parts


_KEY = re.compile(r"^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*([\s\S]*?)\s*$")
_STRING_KEY = re.compile(r"^\s*['\"]([^'\"]+)['\"]\s*:\s*([\s\S]*?)\s*$")
_LITERAL_STRING = re.compile(r"^['\"]([^'\"]*)['\"]$")


def request_body_fields(body: Any) -> dict[str, str]:
    """The top-level keys of the JSON object an HTTP Request node sends, with their raw value text.

    n8n serialises this body as a JS expression string, so it is read as a *structure* (the object literal's
    own top-level keys) rather than by scanning the node for keywords. A body that is an opaque expression
    with no readable object literal (``JSON.stringify($json.request)``) yields no fields — which is exactly
    why an endpoint-registry match, not this reader, is what carries such a call.
    """
    if not isinstance(body, str) or not body.strip():
        return {}
    text = _strip_expression_wrapper(body)
    start = text.find("{")
    if start == -1:
        return {}
    end = _matching_close(text, start, "{", "}")
    if end == -1:
        return {}
    fields: dict[str, str] = {}
    for part in _split_top_level(text[start + 1:end]):
        match = _KEY.match(part) or _STRING_KEY.match(part)
        if match:
            fields[str(match.group(1))] = str(match.group(2)).strip()
    return fields


def _declared_body(node: Mapping[str, Any]) -> Any:
    parameters = node.get("parameters") if isinstance(node.get("parameters"), Mapping) else {}
    if not parameters.get("sendBody"):
        return None
    specify = str(parameters.get("specifyBody") or "").lower()
    if specify and specify != "json":
        return parameters.get("bodyParameters")
    return parameters.get("jsonBody")


def _credential_names(node: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    credentials = node.get("credentials")
    if not isinstance(credentials, Mapping):
        return (), ()
    types: list[str] = []
    names: list[str] = []
    for key, value in credentials.items():
        types.append(str(key))
        if isinstance(value, Mapping) and value.get("name"):
            names.append(str(value["name"]))
    return tuple(types), tuple(names)


# ------------------------------------------------------------------------------------------ the verdict

@dataclass(frozen=True)
class AiSurfaceVerdict:
    """One node's AI-surface verdict, with the evidence that produced it."""

    node: str
    node_type: str
    verdict: str
    how: str = ""
    why: str = ""
    provider: str = ""
    evidence: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_ai(self) -> bool:
        return self.verdict == "AI"

    def as_record(self) -> dict[str, Any]:
        return {"node": self.node, "node_type": self.node_type, "verdict": self.verdict,
                "provider": self.provider, "how": self.how, "why": self.why,
                "evidence": dict(self.evidence)}


def detect_http_ai_surface(node: Mapping[str, Any]) -> AiSurfaceVerdict:
    """Decide one HTTP Request node's AI-surface verdict from grounded, structural evidence."""
    parameters = node.get("parameters") if isinstance(node.get("parameters"), Mapping) else {}
    name = str(node.get("name") or node.get("id") or "")
    node_type = str(node.get("type") or "")
    url = str(parameters.get("url") or "")
    method = str(parameters.get("method") or "GET").upper()
    body = _declared_body(node)
    fields = request_body_fields(body)
    body_declared = body is not None and (isinstance(body, str) and bool(body.strip()) or
                                          isinstance(body, (list, Mapping)) and bool(body))
    model_field = next((key for key in fields if key.lower() in MODEL_FIELDS), "")
    shape_fields = sorted(key for key in fields if key.lower() in AI_SHAPE_FIELDS)
    literal_model = ""
    if model_field:
        literal = _LITERAL_STRING.match(fields.get(model_field, ""))
        literal_model = literal.group(1) if literal else ""
    credential_types, credential_names = _credential_names(node)

    endpoint_rule: ProviderRule | None = None
    endpoint_pattern = ""
    for rule in PROVIDER_RULES:
        matched = rule.endpoint_match(url)
        if matched:
            endpoint_rule, endpoint_pattern = rule, matched
            break
    model_rule: ProviderRule | None = None
    model_pattern = ""
    if literal_model:
        for rule in PROVIDER_RULES:
            matched = rule.model_match(literal_model)
            if matched:
                model_rule, model_pattern = rule, matched
                break
    credential_hit = ""
    credential_rule: ProviderRule | None = None
    for rule in PROVIDER_RULES:
        hit = rule.credential_match(credential_types, credential_names)
        if hit:
            credential_rule, credential_hit = rule, hit
            break

    supports_ai = bool(model_field or shape_fields)
    write_with_body = method in WRITE_METHODS and bool(body_declared)
    references_item_data = isinstance(body, str) and bool(re.search(r"\$(?:json|input|item)\b", body))
    evidence = {
        "url": url, "method": method, "body_declared": bool(body_declared),
        "model_field": model_field, "model_literal": literal_model,
        "ai_shape_fields": shape_fields, "endpoint_pattern": endpoint_pattern,
        "model_pattern": model_pattern, "credential_hit": credential_hit,
        "references_item_data": references_item_data,
    }

    # 1. A registered AI provider endpoint, with a request that supports AI use.
    if endpoint_rule is not None and (supports_ai or write_with_body):
        how = (f"provider registry endpoint match {endpoint_pattern!r} on {url!r}"
               + (f" and structured AI request contract (model field {model_field!r})" if model_field else "")
               + (f" and AI request shape {shape_fields}" if shape_fields else "")
               + (" and a declared request body" if write_with_body and not supports_ai else ""))
        return AiSurfaceVerdict(name, node_type, "AI", how=how, provider=endpoint_rule.provider,
                                why=f"the destination is a registered {endpoint_rule.provider} AI provider "
                                    f"endpoint and the request shape supports a model call", evidence=evidence)

    # 2. A structured AI request contract: a model field *and* an AI-shaped field, even without a known endpoint.
    if model_field and shape_fields:
        how = (f"structured AI request contract: top-level body keys {sorted(fields)!r} declare model field "
               f"{model_field!r} and AI shape {shape_fields}")
        return AiSurfaceVerdict(name, node_type, "AI", how=how,
                                provider=model_rule.provider if model_rule else "",
                                why="the request body declares both a model and an AI-shaped field, which only "
                                    "a model call does", evidence=evidence)

    # 3. A destination the registry says is not an AI provider.
    non_ai = non_ai_match(url)
    if non_ai:
        return AiSurfaceVerdict(name, node_type, "NOT_AI",
                                how=f"known non-AI destination registry match {non_ai!r}",
                                why="the destination is a registered non-AI data/payment service, so this is "
                                    "not a model call", evidence=evidence)

    # 4. A provider credential alone, contradicted by the request shape.
    if credential_rule is not None and not supports_ai:
        return AiSurfaceVerdict(name, node_type, "NOT_AI",
                                how=f"provider credential {credential_hit!r} but the request shape contradicts "
                                    f"AI use (method {method}, body declared {bool(body_declared)}, no model "
                                    f"and no AI-shaped field)",
                                why="a credential alone is not evidence of a model call, and this request shape "
                                    "does not support one", evidence=evidence)

    # 5. Nothing settles it: ambiguous, partial evidence. Never guessed into either bucket.
    reasons: list[str] = []
    if endpoint_rule is not None:
        reasons.append(f"a registered provider endpoint {endpoint_pattern!r} with a request shape that does "
                       f"not support AI use")
    if model_field:
        reasons.append(f"a model-like field {model_field!r} without a supporting AI-shaped field")
    if shape_fields:
        reasons.append(f"AI-shaped body fields {shape_fields} without a model field or known provider")
    if credential_rule is not None:
        reasons.append(f"a provider credential {credential_hit!r} with a request shape that neither "
                       f"supports nor contradicts AI use")
    if not reasons:
        reasons.append("no model field, provider endpoint or provider credential")
    return AiSurfaceVerdict(name, node_type, "UNRESOLVED",
                            how="; ".join(reasons),
                            why="the evidence is insufficient to claim an AI surface and insufficient to rule "
                                "one out, so the node is left unresolved", evidence=evidence)


@dataclass(frozen=True)
class AiSurfaceReport:
    """Every node's AI-surface verdict for one workflow, with the claimed AI surfaces separated out."""

    verdicts: tuple[AiSurfaceVerdict, ...] = ()

    @property
    def claimed(self) -> tuple[AiSurfaceVerdict, ...]:
        return tuple(item for item in self.verdicts if item.verdict == "AI")

    @property
    def not_ai(self) -> tuple[AiSurfaceVerdict, ...]:
        return tuple(item for item in self.verdicts if item.verdict == "NOT_AI")

    @property
    def unresolved(self) -> tuple[AiSurfaceVerdict, ...]:
        return tuple(item for item in self.verdicts if item.verdict == "UNRESOLVED")

    @property
    def surfaces(self) -> tuple[str, ...]:
        """The node names of the claimed AI surfaces, in declaration order."""
        seen: list[str] = []
        for item in self.claimed:
            if item.node and item.node not in seen:
                seen.append(item.node)
        return tuple(seen)

    @property
    def evidence(self) -> tuple[dict[str, Any], ...]:
        return tuple(item.as_record() for item in self.verdicts)


#: Node types whose AI surface is structural (a native AI node) and therefore already decided by
#: :func:`breaker.readiness.profile.classify_node_type`. The HTTP detector does not touch these; it exists to cover
#: the calls that reader cannot see.
HTTP_REQUEST_NODE_TYPES: tuple[str, ...] = ("n8n-nodes-base.httpRequest",)


def detect_ai_surfaces(workflow: Mapping[str, Any] | None) -> AiSurfaceReport:
    """Detect HTTP-Request AI surfaces in an n8n workflow export. Native AI nodes are left to the node reader."""
    nodes = [item for item in ((workflow or {}).get("nodes") or ()) if isinstance(item, Mapping)]
    verdicts: list[AiSurfaceVerdict] = []
    for node in nodes:
        node_type = str(node.get("type") or "")
        if node_type in HTTP_REQUEST_NODE_TYPES:
            verdicts.append(detect_http_ai_surface(node))
    return AiSurfaceReport(verdicts=tuple(verdicts))


def provider_registry_record() -> dict[str, Any]:
    """The provider registry and the non-AI destination registry, as a machine-readable record."""
    return {
        "providers": [
            {"provider": rule.provider, "endpoint_patterns": list(rule.endpoint_patterns),
             "model_patterns": list(rule.model_patterns), "credential_types": list(rule.credential_types),
             "credential_names": list(rule.credential_names), "note": rule.note}
            for rule in PROVIDER_RULES],
        "non_ai_destinations": [{"pattern": pattern, "why": why}
                                for pattern, why in NON_AI_ENDPOINT_PATTERNS],
        "model_fields": sorted(MODEL_FIELDS),
        "ai_shape_fields": sorted(AI_SHAPE_FIELDS),
    }


def classify_http_surfaces(workflow: Mapping[str, Any] | None) -> dict[str, Any]:
    """Convenience summary used by the profile: claimed names, unknowns and the evidence records.

    ``consumes_item_data`` names the claimed AI surfaces whose request body references the workflow item
    (``$json``/``$input``), i.e. the model is fed data the workflow received. Combined with an external intake
    trigger this is the structural proof that untrusted content reaches the model.
    """
    report = detect_ai_surfaces(workflow)
    return {
        "surfaces": list(report.surfaces),
        "unresolved": [item.node for item in report.unresolved],
        "not_ai": [item.node for item in report.not_ai],
        "consumes_item_data": [item.node for item in report.claimed
                               if item.evidence.get("references_item_data")],
        "evidence": list(report.evidence),
    }


__all__ = [
    "AI_SHAPE_FIELDS", "AiSurfaceReport", "AiSurfaceVerdict", "MODEL_FIELDS", "NON_AI_ENDPOINT_PATTERNS",
    "PROVIDER_RULES", "ProviderRule", "classify_http_surfaces", "detect_ai_surfaces", "detect_http_ai_surface",
    "non_ai_match", "provider_registry_record", "request_body_fields",
]
