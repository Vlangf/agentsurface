from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response

from app.ai_attacks import generate_ai_attack_cases
from app.db import list_runs
from app.models import RunRequest, RunResult, TestPack
from app.runner import run_test_pack
from app.test_packs import build_test_cases, get_test_pack, list_test_packs

app = FastAPI(title="AgentSurface", version="0.1.0")


def _cases_from_request(request: RunRequest):
    cases = build_test_cases(
        request.test_pack_id,
        request.custom_prompts,
        request.include_selected_pack,
        request.mutation_mode,
    )
    if request.ai_generate_attacks:
        cases.extend(generate_ai_attack_cases(request.ai_attack_context, request.ai_attack_count))
    return cases


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/test-packs", response_model=list[TestPack])
def test_packs() -> list[TestPack]:
    return list_test_packs()


@app.post("/runs", response_model=RunResult)
def create_run(request: RunRequest) -> RunResult:
    try:
        cases = _cases_from_request(request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return run_test_pack(request.config, cases, llm_evaluate_responses=request.llm_evaluate_responses)


@app.get("/runs")
def runs() -> list[dict]:
    return list_runs()


@app.post("/reports/json")
def report_json(request: RunRequest) -> dict:
    try:
        cases = _cases_from_request(request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    run = run_test_pack(request.config, cases, llm_evaluate_responses=request.llm_evaluate_responses)
    return run.report


@app.post("/lobster-trap.yaml")
def lobster_trap_yaml(request: RunRequest) -> Response:
    try:
        cases = _cases_from_request(request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    run = run_test_pack(request.config, cases, llm_evaluate_responses=request.llm_evaluate_responses)
    return Response(content=run.lobster_trap_yaml, media_type="application/x-yaml")
