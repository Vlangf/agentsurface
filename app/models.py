from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator


class AdapterConfig(BaseModel):
    endpoint_url: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    request_template: dict[str, Any] = Field(default_factory=dict)
    input_path: str
    output_path: str | None = None
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)

    @field_validator("endpoint_url")
    @classmethod
    def validate_endpoint_url(cls, value: str) -> str:
        # Keep a string field for local/private endpoints, but validate basic URL shape.
        HttpUrl(value)
        return value

    @field_validator("input_path", "output_path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value or any(part == "" for part in value.split(".")):
            raise ValueError("path must be a non-empty dot path, e.g. messages.0.content")
        return value


class TestCase(BaseModel):
    __test__ = False

    id: str
    name: str
    category: str
    prompt: str
    severity: Literal["low", "medium", "high", "critical"] = "medium"


class TestPack(BaseModel):
    id: str
    name: str
    description: str
    cases: list[TestCase]


class AgentCallResult(BaseModel):
    status_code: int | None = None
    extracted_output: str = ""
    raw_response: dict[str, Any] = Field(default_factory=dict)
    masked_request: dict[str, Any] = Field(default_factory=dict)
    elapsed_ms: int = 0
    error: str | None = None


class Finding(BaseModel):
    failed: bool
    risk_score: int
    failure_types: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommendation_ids: list[str] = Field(default_factory=list)


class TestResult(BaseModel):
    test_case: TestCase
    call: AgentCallResult
    finding: Finding
    output: str = ""
    masked_request: dict[str, Any] = Field(default_factory=dict)
    raw_response: dict[str, Any] = Field(default_factory=dict)


class RunSummary(BaseModel):
    total: int
    failed: int
    passed: int
    risk_score: int


class RunResult(BaseModel):
    id: int | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    config: AdapterConfig
    summary: RunSummary
    results: list[TestResult]
    report: dict[str, Any]
    lobster_trap_yaml: str


class RunRequest(BaseModel):
    config: AdapterConfig
    test_pack_id: str = "baseline"
    custom_prompts: str = ""
    include_selected_pack: bool = True
    mutation_mode: bool = False
    ai_generate_attacks: bool = False
    ai_attack_context: str = ""
    ai_attack_count: int = Field(default=5, ge=1, le=20)
    llm_evaluate_responses: bool | None = None
