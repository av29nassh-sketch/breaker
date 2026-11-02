from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol


#: Canonical environment variable naming Breaker's Command Code API key.
COMMAND_CODE_API_KEY_ENV = "COMMAND_CODE_API_KEY"

#: Backward-compatible alias for the same key. The authorized local
#: environment historically exposes the credential under this name, so it must
#: keep resolving; it is deprecated in favour of the canonical name.
COMMANDCODE_API_KEY_ENV = "COMMANDCODE_API_KEY"


def resolve_api_key(
    env: Mapping[str, str],
    *,
    canonical: str = COMMAND_CODE_API_KEY_ENV,
    legacy: str = COMMANDCODE_API_KEY_ENV,
) -> str:
    """Resolve the Command Code API key from an environment mapping.

    Precedence is explicit and tested:

    1. only ``canonical`` set -> use it;
    2. only ``legacy`` set   -> use it (backward-compatible alias);
    3. both set, equal       -> use the shared value;
    4. both set, different   -> fail safely (ambiguous configuration), naming
       the variables but never echoing either value;
    5. neither set           -> fail closed.

    Blank/whitespace-only values count as unset.
    """
    canonical_value = (env.get(canonical) or "").strip()
    legacy_value = (env.get(legacy) or "").strip()
    if canonical_value and legacy_value:
        if canonical_value != legacy_value:
            raise ProviderError(
                "CONFIGURATION_ERROR",
                f"ambiguous provider key: both {canonical} and {legacy} are set with different values; "
                "unset one so a single authorized reference resolves",
            )
        return canonical_value
    if canonical_value:
        return canonical_value
    if legacy_value:
        return legacy_value
    raise ProviderError(
        "CONFIGURATION_ERROR",
        f"required environment variable {canonical} (alias {legacy}) is missing",
    )


class ModelRole(str, Enum):
    DECISION = "BREAKER_DECISION_MODEL"
    REASONING = "BREAKER_REASONING_MODEL"


class ModelOperation(str, Enum):
    DECISION = "DECISION"
    SEMANTIC_SYNTHESIS = "SEMANTIC_SYNTHESIS"
    DIAGNOSIS = "DIAGNOSIS"


@dataclass(frozen=True)
class ModelSpec:
    role: ModelRole
    model_id: str
    endpoint: str


@dataclass(frozen=True)
class ProviderConfig:
    decision: ModelSpec
    reasoning: ModelSpec
    api_key_env: str = COMMAND_CODE_API_KEY_ENV
    legacy_api_key_env: str = COMMANDCODE_API_KEY_ENV
    timeout_seconds: float = 30.0
    max_retries: int = 2
    decision_timeout_seconds: float = 30.0
    synthesis_timeout_seconds: float = 120.0
    diagnosis_timeout_seconds: float = 60.0
    max_timeout_seconds: float = 180.0
    decision_max_retries: int = 2
    synthesis_max_retries: int = 1
    diagnosis_max_retries: int = 1
    measured_synthesis_latency_seconds: float | None = None

    @classmethod
    def default(cls) -> "ProviderConfig":
        return cls(
            decision=ModelSpec(ModelRole.DECISION, "typesafe/jev", "https://api.commandcode.ai/provider/v1/systemone"),
            reasoning=ModelSpec(ModelRole.REASONING, "deepseek/deepseek-v4-flash", "https://api.commandcode.ai/provider/v1/chat/completions"),
        )

    def for_role(self, role: ModelRole) -> ModelSpec:
        return self.decision if role == ModelRole.DECISION else self.reasoning

    def timeout_for(self, operation: ModelOperation) -> float:
        value = {
            ModelOperation.DECISION: self.decision_timeout_seconds,
            ModelOperation.SEMANTIC_SYNTHESIS: self.synthesis_timeout_seconds,
            ModelOperation.DIAGNOSIS: self.diagnosis_timeout_seconds,
        }[operation]
        return min(float(value), float(self.max_timeout_seconds))

    def max_retries_for(self, operation: ModelOperation) -> int:
        value = {
            ModelOperation.DECISION: self.decision_max_retries,
            ModelOperation.SEMANTIC_SYNTHESIS: self.synthesis_max_retries,
            ModelOperation.DIAGNOSIS: self.diagnosis_max_retries,
        }[operation]
        return min(int(value), int(self.max_retries))

    def as_dict(self) -> Mapping[str, Any]:
        return {
            "decision": {"role": self.decision.role.value, "model_id": self.decision.model_id, "endpoint": self.decision.endpoint},
            "reasoning": {"role": self.reasoning.role.value, "model_id": self.reasoning.model_id, "endpoint": self.reasoning.endpoint},
            "api_key_env": self.api_key_env,
            "legacy_api_key_env": self.legacy_api_key_env,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "operation_timeouts": {operation.value: self.timeout_for(operation) for operation in ModelOperation},
            "operation_max_retries": {operation.value: self.max_retries_for(operation) for operation in ModelOperation},
            "max_timeout_seconds": self.max_timeout_seconds,
        }


@dataclass(frozen=True)
class ProviderResult:
    role: ModelRole
    model_id: str
    payload: Mapping[str, Any]
    usage: Mapping[str, Any]
    attempts: int

    def as_dict(self) -> Mapping[str, Any]:
        return {"role": self.role.value, "model_id": self.model_id, "payload": dict(self.payload), "usage": dict(self.usage), "attempts": self.attempts}


class ProviderError(RuntimeError):
    def __init__(self, kind: str, message: str, *, retryable: bool = False, status_code: int | None = None, server_side: bool = False):
        super().__init__(message)
        self.kind = kind
        self.retryable = retryable
        self.status_code = status_code
        self.server_side = server_side


def classify_provider_failure(error: ProviderError) -> str:
    """Every provider failure is inconclusive evidence, never a semantic verdict."""
    return "INCONCLUSIVE_PROVIDER_FAILURE"


class Transport(Protocol):
    def post(self, url: str, *, headers: Mapping[str, str], body: Mapping[str, Any], timeout_seconds: float) -> Mapping[str, Any]: ...


class UrllibTransport:
    def post(self, url: str, *, headers: Mapping[str, str], body: Mapping[str, Any], timeout_seconds: float) -> Mapping[str, Any]:
        request = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=dict(headers), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            if exc.code in {408, 504}:
                raise ProviderError("PROVIDER_TIMEOUT", f"provider returned HTTP {exc.code}", retryable=True, status_code=exc.code, server_side=True) from None
            retryable = exc.code == 429 or exc.code >= 500
            raise ProviderError("HTTP_ERROR", f"provider returned HTTP {exc.code}", retryable=retryable, status_code=exc.code) from None
        except TimeoutError as exc:
            raise ProviderError("PROVIDER_TIMEOUT", f"provider transport failed: {type(exc).__name__}", retryable=True, server_side=False) from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise ProviderError("PROVIDER_TIMEOUT", "provider transport failed: TimeoutError", retryable=True, server_side=False) from None
            raise ProviderError("TRANSPORT_ERROR", f"provider transport failed: {type(exc).__name__}", retryable=True) from None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            raise ProviderError("MALFORMED_RESPONSE", "provider returned non-JSON content") from None
        if not isinstance(parsed, Mapping):
            raise ProviderError("MALFORMED_RESPONSE", "provider returned a non-object JSON value")
        return parsed


class BreakerModelProvider:
    def __init__(self, api_key: str, *, config: ProviderConfig | None = None, transport: Transport | None = None):
        if not api_key:
            raise ProviderError("CONFIGURATION_ERROR", "Command Code API key is missing")
        self._api_key = api_key
        self.config = config or ProviderConfig.default()
        self.transport = transport or UrllibTransport()

    @classmethod
    def from_environment(cls, *, config: ProviderConfig | None = None, transport: Transport | None = None) -> "BreakerModelProvider":
        cfg = config or ProviderConfig.default()
        api_key = resolve_api_key(os.environ, canonical=cfg.api_key_env, legacy=cfg.legacy_api_key_env)
        return cls(api_key, config=cfg, transport=transport)

    def decide(self, request: Mapping[str, Any]) -> ProviderResult:
        spec = self.config.for_role(ModelRole.DECISION)
        body = dict(request)
        body["model"] = spec.model_id
        result = self._post(spec, body, ModelOperation.DECISION)
        if "answers" not in result.payload or not isinstance(result.payload["answers"], Mapping):
            raise ProviderError("MALFORMED_RESPONSE", "Jev response has no answers object")
        return result

    def reason(self, prompt: str, *, system: str | None = None, operation: ModelOperation = ModelOperation.SEMANTIC_SYNTHESIS) -> ProviderResult:
        spec = self.config.for_role(ModelRole.REASONING)
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        result = self._post(spec, {"model": spec.model_id, "messages": messages, "temperature": 0, "response_format": {"type": "json_object"}}, operation)
        choices = result.payload.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
            raise ProviderError("MALFORMED_RESPONSE", "V4 response has no choices")
        message = choices[0].get("message")
        if not isinstance(message, Mapping) or not isinstance(message.get("content"), str):
            raise ProviderError("MALFORMED_RESPONSE", "V4 response has no message content")
        return result

    def _post(self, spec: ModelSpec, body: Mapping[str, Any], operation: ModelOperation) -> ProviderResult:
        timeout = self.config.timeout_for(operation)
        retries = self.config.max_retries_for(operation)
        attempts = 0
        last: ProviderError | None = None
        for attempt in range(retries + 1):
            attempts += 1
            try:
                payload = self.transport.post(spec.endpoint, headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"}, body=body, timeout_seconds=timeout)
                if not isinstance(payload, Mapping):
                    raise ProviderError("MALFORMED_RESPONSE", "provider response is not an object")
                model_id = payload.get("model")
                if model_id != spec.model_id:
                    raise ProviderError("MODEL_ID_MISMATCH", f"provider returned unexpected model for role {spec.role.value}")
                usage = payload.get("usage")
                if not isinstance(usage, Mapping):
                    raise ProviderError("MALFORMED_RESPONSE", "provider response has no usage object")
                return ProviderResult(spec.role, spec.model_id, payload, usage, attempts)
            except ProviderError as exc:
                last = exc
                if not exc.retryable or attempt >= retries:
                    raise
                time.sleep(min(0.25 * (2 ** attempt), 1.0))
            except TimeoutError as exc:
                timeout_error = ProviderError("PROVIDER_TIMEOUT", f"provider transport failed: {type(exc).__name__}", retryable=True, server_side=False)
                last = timeout_error
                if attempt >= retries:
                    raise timeout_error from None
                time.sleep(min(0.25 * (2 ** attempt), 1.0))
        raise last or ProviderError("INCONCLUSIVE", "provider call did not produce a result")


@dataclass(frozen=True)
class ShadowDecision:
    decision_family: str
    deterministic_input_hash: str
    model: str
    answer: Any
    confidence: float | None
    known_truth: Any | None
    status: str = "SHADOW_ONLY"

    def as_dict(self) -> Mapping[str, Any]:
        return {"decision_family": self.decision_family, "deterministic_input_hash": self.deterministic_input_hash, "model": self.model, "answer": self.answer, "confidence": self.confidence, "known_truth": self.known_truth, "status": self.status}
