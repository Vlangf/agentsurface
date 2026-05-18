from __future__ import annotations

from copy import deepcopy
from time import perf_counter
from typing import Any

import httpx

from app.models import AdapterConfig, AgentCallResult

SENSITIVE_HEADER_MARKERS = ("authorization", "api-key", "apikey", "token", "secret", "cookie")
COMMON_OUTPUT_PATHS = (
    "choices.0.message.content",
    "choices.0.text",
    "message.content",
    "answer",
    "reply.text",
    "reply",
    "response",
    "result.response",
    "result.text",
    "result.message.content",
    "data.output",
    "data.answer",
    "output",
    "text",
    "content",
)
OUTPUT_KEY_HINTS = ("answer", "reply", "response", "output", "text", "content", "message")


class AdapterError(RuntimeError):
    pass


def _path_parts(path: str) -> list[str]:
    return path.split(".") if path else []


def set_path(payload: Any, path: str, value: Any) -> None:
    current = payload
    parts = _path_parts(path)
    for part in parts[:-1]:
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]
    last = parts[-1]
    if isinstance(current, list):
        current[int(last)] = value
    else:
        current[last] = value


def get_path(payload: Any, path: str) -> Any:
    current = payload
    for part in _path_parts(path):
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]
    return current


def _best_string_in_json(payload: Any) -> str | None:
    candidates: list[tuple[int, str]] = []

    def walk(value: Any, path: list[str]) -> None:
        if isinstance(value, str) and value.strip():
            key = path[-1].lower() if path else ""
            score = min(len(value), 100)
            if key in OUTPUT_KEY_HINTS:
                score += 100
            elif any(hint in key for hint in OUTPUT_KEY_HINTS):
                score += 40
            candidates.append((score, value))
        elif isinstance(value, dict):
            for key, child in value.items():
                walk(child, [*path, str(key)])
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, [*path, str(index)])

    walk(payload, [])
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def extract_output(payload: Any, output_path: str | None = None) -> str:
    if output_path:
        value = get_path(payload, output_path)
        return value if isinstance(value, str) else str(value)

    for path in COMMON_OUTPUT_PATHS:
        try:
            value = get_path(payload, path)
        except (KeyError, IndexError, ValueError, TypeError):
            continue
        if isinstance(value, str) and value.strip():
            return value
        if value is not None and not isinstance(value, (dict, list)):
            return str(value)

    found = _best_string_in_json(payload)
    if found is not None:
        return found
    return str(payload)


def mask_headers(headers: dict[str, str]) -> dict[str, str]:
    masked: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if any(marker in lower for marker in SENSITIVE_HEADER_MARKERS):
            masked[key] = "***MASKED***"
        else:
            masked[key] = value
    return masked


def build_request_body(config: AdapterConfig, prompt: str) -> dict[str, Any]:
    body = deepcopy(config.request_template)
    try:
        set_path(body, config.input_path, prompt)
    except (KeyError, IndexError, ValueError, TypeError) as exc:
        raise AdapterError(f"Invalid input_path '{config.input_path}': {exc}") from exc
    return body


class AgentClient:
    def __init__(self, config: AdapterConfig, http_client: httpx.Client | None = None):
        self.config = config
        self.http_client = http_client
        self._owns_client = http_client is None

    def close(self) -> None:
        if self._owns_client and self.http_client is not None:
            self.http_client.close()

    def __enter__(self) -> "AgentClient":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def call(self, prompt: str) -> AgentCallResult:
        body = build_request_body(self.config, prompt)
        masked_request = {
            "method": self.config.method,
            "url": self.config.endpoint_url,
            "headers": mask_headers(self.config.headers),
            "json": body,
            "timeout_seconds": self.config.timeout_seconds,
        }
        client = self.http_client or httpx.Client(timeout=self.config.timeout_seconds)
        started = perf_counter()
        try:
            response = client.request(
                self.config.method,
                self.config.endpoint_url,
                headers=self.config.headers,
                json=body,
                timeout=self.config.timeout_seconds,
            )
            elapsed_ms = int((perf_counter() - started) * 1000)
            try:
                response_json = response.json()
            except ValueError:
                response_json = None
            raw_response = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "json": response_json,
                "text": response.text if response_json is None else None,
                "raw_response_text": response.text,
            }
            if response.status_code >= 400:
                return AgentCallResult(
                    status_code=response.status_code,
                    raw_response=raw_response,
                    masked_request=masked_request,
                    elapsed_ms=elapsed_ms,
                    error=f"Agent API returned HTTP {response.status_code}: {response.text[:500]}",
                )
            if response_json is None:
                extracted = response.text
            else:
                try:
                    extracted = extract_output(response_json, self.config.output_path)
                except (KeyError, IndexError, ValueError, TypeError) as exc:
                    return AgentCallResult(
                        status_code=response.status_code,
                        raw_response=raw_response,
                        masked_request=masked_request,
                        elapsed_ms=elapsed_ms,
                        error=f"Could not extract agent response from JSON: {exc}",
                    )
            return AgentCallResult(
                status_code=response.status_code,
                extracted_output=extracted,
                raw_response=raw_response,
                masked_request=masked_request,
                elapsed_ms=elapsed_ms,
            )
        except httpx.TimeoutException as exc:
            elapsed_ms = int((perf_counter() - started) * 1000)
            return AgentCallResult(
                masked_request=masked_request,
                elapsed_ms=elapsed_ms,
                error=f"Agent API timed out after {self.config.timeout_seconds} seconds: {exc}",
            )
        except httpx.RequestError as exc:
            elapsed_ms = int((perf_counter() - started) * 1000)
            return AgentCallResult(
                masked_request=masked_request,
                elapsed_ms=elapsed_ms,
                error=f"Agent API request failed: {exc}",
            )
