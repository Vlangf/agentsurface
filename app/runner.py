from __future__ import annotations

from pathlib import Path
from typing import Iterable

import httpx

from app.agent_client import AgentClient
from app.db import DEFAULT_DB_PATH, save_run
from app.evaluator import evaluate_security_failures
from app.llm_evaluator import evaluate_response_with_llm, llm_response_evaluation_available
from app.lobster_trap import generate_lobster_trap_yaml
from app.models import AdapterConfig, RunResult, RunSummary, TestCase, TestResult


def _evaluation_text(call) -> str:
    parts = []
    if call.extracted_output:
        parts.append(f"EXTRACTED_OUTPUT:\n{call.extracted_output}")
    raw_text = call.raw_response.get("raw_response_text") or call.raw_response.get("text")
    if raw_text and raw_text != call.extracted_output:
        parts.append(f"RAW_RESPONSE_TEXT:\n{raw_text}")
    return "\n\n".join(parts)


def _build_report(results: list[TestResult], summary: RunSummary) -> dict:
    failures: dict[str, int] = {}
    for result in results:
        for failure in result.finding.failure_types:
            failures[failure] = failures.get(failure, 0) + 1
    return {
        "summary": summary.model_dump(),
        "failures_by_type": failures,
        "failed_tests": [
            {
                "id": result.test_case.id,
                "name": result.test_case.name,
                "category": result.test_case.category,
                "risk_score": result.finding.risk_score,
                "failure_types": result.finding.failure_types,
                "evidence": result.finding.evidence,
            }
            for result in results
            if result.finding.failed
        ],
        "raw_results": [result.model_dump() for result in results],
    }


def run_test_pack(
    config: AdapterConfig,
    cases: Iterable[TestCase],
    db_path: str | Path = DEFAULT_DB_PATH,
    http_client: httpx.Client | None = None,
    persist: bool = True,
    llm_evaluate_responses: bool | None = None,
    llm_http_client: httpx.Client | None = None,
) -> RunResult:
    if llm_evaluate_responses is None:
        llm_evaluate_responses = llm_response_evaluation_available()

    results: list[TestResult] = []
    with AgentClient(config, http_client=http_client) as client:
        for case in cases:
            call = client.call(case.prompt)
            evaluation_text = _evaluation_text(call)
            finding = evaluate_security_failures(case, evaluation_text, call.error)
            if llm_evaluate_responses and not call.error:
                llm_finding = evaluate_response_with_llm(
                    case,
                    evaluation_text,
                    call.masked_request.get("json", {}),
                    http_client=llm_http_client,
                )
                if llm_finding.risk_score > finding.risk_score:
                    finding = llm_finding
            results.append(
                TestResult(
                    test_case=case,
                    call=call,
                    finding=finding,
                    output=call.extracted_output,
                    masked_request=call.masked_request,
                    raw_response=call.raw_response,
                )
            )
    failed = sum(1 for result in results if result.finding.failed)
    risk_score = max((result.finding.risk_score for result in results), default=0)
    summary = RunSummary(total=len(results), failed=failed, passed=len(results) - failed, risk_score=risk_score)
    all_failures: list[str] = []
    for result in results:
        all_failures.extend(result.finding.failure_types)
    lobster_yaml = generate_lobster_trap_yaml(list(dict.fromkeys(all_failures)), risk_score)
    report = _build_report(results, summary)
    run = RunResult(config=config, summary=summary, results=results, report=report, lobster_trap_yaml=lobster_yaml)
    if persist:
        run.id = save_run(run, db_path)
    return run
