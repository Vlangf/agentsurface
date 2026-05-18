from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

# Allows `streamlit run ui/streamlit_app.py` from repo root without installing package.
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.ai_attacks import ai_attack_generation_available, generate_ai_attack_cases
from app.agent_client import build_request_body
from app.db import get_attack_set, list_attack_sets, list_runs, save_attack_set
from app.llm_evaluator import llm_response_evaluation_available
from app.models import AdapterConfig, TestCase
from app.runner import run_test_pack
from app.test_packs import list_prompt_source_packs, list_test_packs

st.set_page_config(page_title="AgentSurface", layout="wide", initial_sidebar_state="collapsed")


def _inject_css() -> None:
    st.markdown(
        """
        <style>
        :root {
            --as-bg: #08090a;
            --as-panel: #0f1011;
            --as-surface: #191a1b;
            --as-border: rgba(255,255,255,0.08);
            --as-border-soft: rgba(255,255,255,0.05);
            --as-text: #f7f8f8;
            --as-muted: #8a8f98;
            --as-soft: #d0d6e0;
            --as-accent: #7170ff;
            --as-accent-bg: #5e6ad2;
        }
        .stApp {
            background:
                radial-gradient(circle at 20% -10%, rgba(113,112,255,0.16), transparent 32rem),
                radial-gradient(circle at 80% 0%, rgba(94,106,210,0.10), transparent 28rem),
                var(--as-bg);
            color: var(--as-text);
        }
        .block-container {
            max-width: 1280px;
            padding-top: 2.25rem;
            padding-bottom: 4rem;
        }
        div[data-testid="stToolbar"] {
            opacity: 0.35;
        }
        [data-testid="stSidebar"] { display: none; }
        h1, h2, h3, h4, p, label, span, div {
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        h1, h2, h3 {
            letter-spacing: -0.03em;
        }
        .as-hero {
            padding: 24px 26px;
            border: 1px solid var(--as-border);
            border-radius: 18px;
            background: linear-gradient(180deg, rgba(255,255,255,0.055), rgba(255,255,255,0.018));
            box-shadow: 0 24px 80px rgba(0,0,0,0.32), inset 0 1px 0 rgba(255,255,255,0.05);
            margin-bottom: 18px;
        }
        .as-kicker {
            color: var(--as-accent);
            font-size: 12px;
            font-weight: 650;
            letter-spacing: 0.12em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .as-title {
            color: var(--as-text);
            font-size: 42px;
            line-height: 1.04;
            font-weight: 650;
            letter-spacing: -0.055em;
            margin: 0;
        }
        .as-subtitle {
            color: var(--as-muted);
            font-size: 15px;
            margin-top: 10px;
            max-width: 820px;
        }
        .as-topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            padding: 10px 2px 18px;
        }
        .as-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--as-text);
            font-weight: 650;
            letter-spacing: -0.02em;
        }
        .as-brand-mark {
            width: 22px;
            height: 22px;
            border-radius: 7px;
            background: linear-gradient(135deg, #7170ff, #5e6ad2);
            box-shadow: 0 0 30px rgba(113,112,255,0.36);
        }
        .as-topbar-meta {
            color: var(--as-muted);
            font-size: 12px;
            font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
        }
        .as-section-title {
            margin: 8px 0 4px;
            color: var(--as-text);
            font-size: 24px;
            font-weight: 590;
            letter-spacing: -0.035em;
        }
        .as-section-copy {
            color: var(--as-muted);
            margin: 0 0 16px;
            font-size: 14px;
        }
        .as-grid-card {
            min-height: 116px;
            border: 1px solid var(--as-border);
            border-radius: 16px;
            background: linear-gradient(180deg, rgba(255,255,255,0.045), rgba(255,255,255,0.018));
            padding: 16px 18px;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.035);
            margin-bottom: 14px;
        }
        .as-card-label {
            color: var(--as-muted);
            font-size: 11px;
            font-weight: 650;
            letter-spacing: 0.11em;
            text-transform: uppercase;
            margin-bottom: 8px;
        }
        .as-card-value {
            color: var(--as-text);
            font-size: 28px;
            line-height: 1;
            font-weight: 650;
            letter-spacing: -0.05em;
        }
        .as-card-note {
            color: var(--as-muted);
            font-size: 13px;
            margin-top: 10px;
        }
        .as-command-card {
            border: 1px solid var(--as-border);
            border-radius: 16px;
            background: rgba(255,255,255,0.025);
            padding: 18px;
            margin: 10px 0 18px;
        }
        .as-workspace-card {
            border: 1px solid var(--as-border);
            border-radius: 18px;
            background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.015));
            padding: 18px;
            margin-bottom: 18px;
        }
        .as-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            border: 1px solid var(--as-border);
            border-radius: 999px;
            padding: 4px 10px;
            color: var(--as-soft);
            background: rgba(255,255,255,0.025);
            font-size: 12px;
            font-weight: 510;
        }
        .as-dot {
            width: 7px;
            height: 7px;
            border-radius: 99px;
            background: #10b981;
            box-shadow: 0 0 16px rgba(16,185,129,0.45);
        }
        .as-callout {
            border: 1px solid rgba(113,112,255,0.30);
            border-radius: 14px;
            background: linear-gradient(180deg, rgba(113,112,255,0.115), rgba(255,255,255,0.018));
            padding: 14px 16px;
            margin: 10px 0 14px;
            color: var(--as-soft);
            font-size: 13px;
            line-height: 1.5;
        }
        .as-callout strong {
            color: var(--as-text);
            font-weight: 590;
        }
        .as-callout code {
            color: var(--as-text);
            background: rgba(0,0,0,0.22);
            border: 1px solid rgba(255,255,255,0.08);
            padding: 1px 5px;
            border-radius: 6px;
        }
        div[data-baseweb="tab-list"] {
            gap: 8px;
        }
        div[data-baseweb="tab"] {
            border: 1px solid var(--as-border-soft);
            border-radius: 999px;
            background: rgba(255,255,255,0.025);
            padding: 4px 14px;
        }
        div[data-baseweb="tab-highlight"] {
            background: transparent;
        }
        button[data-testid="stBaseButton-segmented_control"] {
            border-color: var(--as-border) !important;
            background: rgba(255,255,255,0.025) !important;
            color: var(--as-soft) !important;
        }
        button[data-testid="stBaseButton-segmented_controlActive"] {
            border-color: rgba(113,112,255,0.55) !important;
            background: rgba(113,112,255,0.14) !important;
            color: var(--as-text) !important;
            box-shadow: inset 0 0 0 1px rgba(255,255,255,0.035), 0 0 26px rgba(113,112,255,0.12) !important;
        }
        .as-card {
            border: 1px solid var(--as-border);
            border-radius: 14px;
            background: rgba(255,255,255,0.025);
            padding: 16px 18px;
            margin: 8px 0 14px;
        }
        [data-testid="stMetric"] {
            border: 1px solid var(--as-border);
            border-radius: 14px;
            padding: 14px 16px;
            background: rgba(255,255,255,0.025);
        }
        .stButton > button, .stDownloadButton > button {
            border-radius: 10px;
            border: 1px solid var(--as-border) !important;
            background: rgba(255,255,255,0.04) !important;
            color: var(--as-text) !important;
            box-shadow: none !important;
        }
        .stButton > button[kind="primary"], .stButton > button[data-testid="baseButton-primary"] {
            background: linear-gradient(180deg, #7170ff, #5e6ad2) !important;
            border-color: rgba(255,255,255,0.16) !important;
            color: white !important;
        }
        .stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] > div, .stNumberInput input {
            background: rgba(255,255,255,0.035) !important;
            border-color: var(--as-border) !important;
            border-radius: 10px !important;
            color: var(--as-text) !important;
        }
        .stTextArea textarea {
            font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
            font-size: 13px;
        }
        div[data-testid="stExpander"] {
            border: 1px solid var(--as-border) !important;
            border-radius: 14px !important;
            background: rgba(255,255,255,0.02) !important;
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid var(--as-border);
            border-radius: 14px;
            overflow: hidden;
        }
        code, pre {
            border-radius: 12px !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


_inject_css()
st.markdown(
    """
    <div class="as-topbar">
      <div class="as-brand"><span class="as-brand-mark"></span><span>AgentSurface</span></div>
      <div class="as-topbar-meta">Streamlit-only red-team console</div>
    </div>
    <div class="as-hero">
      <div class="as-kicker">Command center</div>
      <h1 class="as-title">Real-agent attack surface testing</h1>
      <div class="as-subtitle">
        Build reusable attack sets, run them against a real HTTP JSON agent, inspect raw traffic,
        and export deployable Lobster Trap policies.
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)


def _prompt_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _append_prompts(current: str, prompts: list[str]) -> str:
    existing = _prompt_lines(current)
    for prompt in prompts:
        if prompt.strip() and prompt.strip() not in existing:
            existing.append(prompt.strip())
    return "\n".join(existing)


def _remove_prompts(current: str, prompts: list[str]) -> str:
    to_remove = {prompt.strip() for prompt in prompts}
    return "\n".join(line for line in _prompt_lines(current) if line not in to_remove)


def _normalize_endpoint_url(value: str) -> str:
    cleaned = value.strip()
    if cleaned and not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"
    return cleaned


def _placeholder_paths(payload: object, placeholder: str = "{{input}}") -> list[str]:
    paths: list[str] = []

    def walk(value: object, path: list[str]) -> None:
        if isinstance(value, str) and value == placeholder:
            paths.append(".".join(path))
        elif isinstance(value, dict):
            for key, child in value.items():
                walk(child, [*path, str(key)])
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, [*path, str(index)])

    walk(payload, [])
    return paths


def _case_from_prompt(index: int, prompt: str) -> TestCase:
    return TestCase(
        id=f"saved-attack-{index}",
        name=f"Saved attack {index}",
        category="saved_attack_set",
        prompt=prompt,
        severity="high",
    )


def _page_intro(title: str, copy: str) -> None:
    st.markdown(
        f"""
        <div>
          <h2 class="as-section-title">{title}</h2>
          <p class="as-section-copy">{copy}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _metric_card(label: str, value: object, note: str = "") -> None:
    st.markdown(
        f"""
        <div class="as-grid-card">
          <div class="as-card-label">{label}</div>
          <div class="as-card-value">{value}</div>
          <div class="as-card-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _result_status(result) -> str:
    if result.call.error:
        return "API error"
    if result.finding.failed:
        return "Attack succeeded"
    return "Attack blocked"


def _result_rows(results) -> list[dict[str, object]]:
    rows = []
    for index, result in enumerate(results, start=1):
        output = result.output or result.call.error or ""
        rows.append(
            {
                "#": index,
                "status": _result_status(result),
                "attack": result.test_case.name,
                "category": result.test_case.category,
                "risk": result.finding.risk_score,
                "failure_types": ", ".join(result.finding.failure_types) or "—",
                "http_status": result.call.status_code or "—",
                "response_preview": output.replace("\n", " ")[:220],
            }
        )
    return rows


def _workspace_card_start(label: str) -> None:
    st.markdown(f'<div class="as-workspace-card"><div class="as-card-label">{label}</div>', unsafe_allow_html=True)


def _workspace_card_end() -> None:
    st.markdown('</div>', unsafe_allow_html=True)


def _sync_attack_pack(pack_id: str, prompts: list[str]) -> None:
    key = f"pack_{pack_id}"
    current = bool(st.session_state.get(key, False))
    previous = bool(st.session_state.pack_checkbox_state.get(pack_id, False))
    if current == previous:
        return

    if current:
        st.session_state.attack_editor_text = _append_prompts(st.session_state.attack_editor_text, prompts)
    else:
        st.session_state.attack_editor_text = _remove_prompts(st.session_state.attack_editor_text, prompts)
    st.session_state.attack_editor_version += 1
    st.session_state.pack_checkbox_state[pack_id] = current


def _run_page() -> None:
    _page_intro("Run dashboard", "Choose a saved attack set, configure the real agent HTTP API, then run tests from one compact workspace.")

    attack_sets = list_attack_sets()
    runs = list_runs()
    stats = st.columns(3)
    with stats[0]:
        _metric_card("Saved sets", len(attack_sets), "Reusable attack libraries")
    with stats[1]:
        _metric_card("Recent runs", len(runs), "Stored in SQLite")
    with stats[2]:
        latest_risk = "—"
        if st.session_state.get("last_run") is not None:
            latest_risk = st.session_state.last_run.summary.risk_score
        elif runs:
            try:
                latest_risk = json.loads(runs[0]["summary_json"]).get("risk_score", "—")
            except Exception:
                latest_risk = "—"
        _metric_card("Latest risk", latest_risk, "Current session or last saved run")
    if not attack_sets:
        st.warning("No saved attack sets yet. Open the Attack Sets page and create one first.")
        return

    set_options = {f"{row['name']} ({row['prompt_count']} prompts)": row["id"] for row in attack_sets}
    selected_set_name = st.selectbox("Saved attack set", list(set_options.keys()))
    selected_set = get_attack_set(set_options[selected_set_name])
    prompts = _prompt_lines(selected_set["prompts_text"])

    with st.expander("Preview selected attack set", expanded=False):
        for index, prompt in enumerate(prompts, start=1):
            st.code(f"{index}. {prompt}")

    _workspace_card_start("Adapter config")
    col1, col2 = st.columns([2, 1])
    with col1:
        endpoint_url_raw = st.text_input(
            "Endpoint URL",
            value="https://example.com/chat",
            key="run_endpoint_url",
            help="Protocol is required; AgentSurface will add http:// if omitted. Docker users can use host.docker.internal to reach apps running on the host.",
        )
        endpoint_url = _normalize_endpoint_url(endpoint_url_raw)
        st.caption(f"Effective URL: `{endpoint_url}`")
    with col2:
        method = st.selectbox("Method", ["POST", "PUT", "PATCH", "GET", "DELETE"], index=0)
    timeout_seconds = st.number_input("Request timeout seconds", min_value=0.1, max_value=300.0, value=30.0)
    st.markdown(
        """
        <div class="as-callout">
          <strong>Prompt injection rule:</strong> the attack prompt is written to the
          <code>Prompt field path</code>. The JSON template is only the starting body.
          Example: for <code>{&quot;user_id&quot;:&quot;u_1001&quot;,&quot;message&quot;:&quot;{{input}}&quot;}</code>, set path to <code>message</code>.
        </div>
        """,
        unsafe_allow_html=True,
    )
    input_path = st.text_input(
        "Prompt field path — the exact JSON field that receives each attack prompt",
        value="input",
        help="Dot path where AgentSurface writes the prompt. Examples: input, message, messages.0.content.",
    )
    headers_text = st.text_area("Headers JSON", value='{"Authorization": "Bearer YOUR_TOKEN"}', height=120)
    template_text = st.text_area(
        "Request JSON template — static body before prompt injection",
        value='{"input": "{{input}}"}',
        height=180,
        help="{{input}} is a visual placeholder. The real write target is Prompt field path above.",
    )

    try:
        preview_template = json.loads(template_text or "{}")
        placeholder_paths = _placeholder_paths(preview_template)
        preview_config = AdapterConfig(
            endpoint_url=endpoint_url,
            method=method,
            headers={},
            request_template=preview_template,
            input_path=input_path,
            timeout_seconds=timeout_seconds,
        )
        preview_prompt = prompts[0] if prompts else "Example attack prompt"
        preview_body = build_request_body(preview_config, preview_prompt)
        if placeholder_paths and input_path not in placeholder_paths:
            st.warning(
                "{{input}} is in "
                f"{', '.join(placeholder_paths)}, but Prompt field path is '{input_path}'. "
                "That placeholder will stay literal unless the path matches it."
            )
        st.caption("Payload preview for the first attack prompt")
        st.json(preview_body)
    except Exception as exc:
        st.error(f"Request template / prompt field path is invalid: {exc}")

    llm_judge_available = llm_response_evaluation_available()
    if llm_judge_available:
        st.caption("LLM response judge is enabled by default for semantic response analysis.")
    else:
        st.info("LLM response judge disabled: set AGENTSURFACE_AI_ATTACK_API_KEY to enable semantic response analysis.")

    run_clicked = st.button("Run selected attack set", type="primary")
    _workspace_card_end()
    if run_clicked:
        try:
            headers = json.loads(headers_text or "{}")
            request_template = json.loads(template_text or "{}")
            config = AdapterConfig(
                endpoint_url=endpoint_url,
                method=method,
                headers=headers,
                request_template=request_template,
                input_path=input_path,
                timeout_seconds=timeout_seconds,
            )
            cases = [_case_from_prompt(index, prompt) for index, prompt in enumerate(prompts, start=1)]
            with st.spinner(f"Calling real agent API with {len(cases)} attacks..."):
                st.session_state.last_run = run_test_pack(
                    config,
                    cases,
                )
        except Exception as exc:
            st.error(f"Run failed: {exc}")

    run = st.session_state.get("last_run")
    if run is None:
        return
    if run.config.endpoint_url != endpoint_url:
        st.info(
            "Results below are from a previous run. Click 'Run selected attack set' "
            f"to test the current Effective URL: {endpoint_url}"
        )
        return

    summary = run.summary
    _page_intro(
        "Run report",
        "Failed = attack succeeded / security issue found. Passed = attack was blocked or no deterministic issue was detected.",
    )
    cols = st.columns(4)
    with cols[0]:
        _metric_card("Total attacks", summary.total, "Prompts executed")
    with cols[1]:
        _metric_card("Attacks succeeded", summary.failed, "Needs review / policy")
    with cols[2]:
        _metric_card("Attacks blocked", summary.passed, "No issue detected")
    with cols[3]:
        _metric_card("Risk score", summary.risk_score, "Max finding severity")

    if summary.failed:
        st.error(f"{summary.failed} attack(s) appear to have succeeded. Open 'Attack details' to inspect prompts and agent replies.")
    else:
        st.success("All attacks were blocked or produced no deterministic security finding.")

    report_tab, details_tab, raw_tab, exports_tab = st.tabs(
        ["Overview", "Attack details", "Raw requests/responses", "Exports"]
    )

    with report_tab:
        st.subheader("Attack outcome table")
        st.dataframe(_result_rows(run.results), use_container_width=True, hide_index=True)
        failures_by_type = run.report.get("failures_by_type", {})
        if failures_by_type:
            st.subheader("Failures by type")
            st.dataframe(
                [
                    {"failure_type": failure_type, "count": count}
                    for failure_type, count in failures_by_type.items()
                ],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.caption("No failure types detected.")

    with details_tab:
        st.subheader("Prompts and agent replies")
        for index, result in enumerate(run.results, start=1):
            status = _result_status(result)
            title = f"{index}. {status} · {result.test_case.name} · risk {result.finding.risk_score}"
            with st.expander(title, expanded=result.finding.failed):
                st.write("Attack prompt")
                st.code(result.test_case.prompt)
                st.write("Agent reply / extracted output")
                st.code(result.output or result.call.error or "<empty response>")
                st.write("Finding")
                st.json(result.finding.model_dump())

    with raw_tab:
        st.subheader("HTTP evidence")
        for index, result in enumerate(run.results, start=1):
            status = _result_status(result)
            with st.expander(f"{index}. {status} · {result.test_case.name}", expanded=False):
                st.write("Masked request")
                st.json(result.masked_request)
                st.write("Raw response")
                st.json(result.raw_response)

    with exports_tab:
        report_json = json.dumps(run.report, indent=2, ensure_ascii=False)
        st.download_button("Export full JSON report", report_json, file_name="agentsurface_report.json", mime="application/json")
        st.download_button(
            "Export Lobster Trap policy YAML",
            run.lobster_trap_yaml,
            file_name="agentsurface_policy.yaml",
            mime="application/x-yaml",
        )
        with st.expander("Full JSON report", expanded=False):
            st.json(run.report)
        with st.expander("Lobster Trap policy YAML", expanded=False):
            st.caption(
                "Policy draft generated from detected failure types. Use the Overview/Attack details tabs first to understand what happened."
            )
            st.code(run.lobster_trap_yaml, language="yaml")


def _attack_sets_page() -> None:
    _page_intro("Attack Sets builder", "Canvas for reusable adversarial prompt sets. One line in the editor = one attack prompt.")

    if "attack_editor_text" not in st.session_state:
        st.session_state.attack_editor_text = ""
    if "attack_editor_version" not in st.session_state:
        st.session_state.attack_editor_version = 0
    if "pack_checkbox_state" not in st.session_state:
        st.session_state.pack_checkbox_state = {}

    stats = st.columns(3)
    existing_sets_for_stats = list_attack_sets()
    built_in_count = sum(len(pack.cases) for pack in list_test_packs())
    with stats[0]:
        _metric_card("Saved sets", len(existing_sets_for_stats), "Reusable libraries")
    with stats[1]:
        _metric_card("Built-in prompts", built_in_count, "Across default packs")
    with stats[2]:
        _metric_card("Editor prompts", len(_prompt_lines(st.session_state.attack_editor_text)), "Current canvas")

    left, right = st.columns([2, 1])
    with left:
        _workspace_card_start("Builder canvas")
        existing_sets = list_attack_sets()
        if existing_sets:
            load_options = {"New attack set": None} | {f"{row['name']} ({row['prompt_count']})": row["id"] for row in existing_sets}
            selected_existing = st.selectbox("Load existing set", list(load_options.keys()))
            if st.button("Load into editor") and load_options[selected_existing] is not None:
                loaded = get_attack_set(load_options[selected_existing])
                st.session_state.attack_set_name = loaded["name"]
                st.session_state.attack_editor_text = loaded["prompts_text"]
                st.session_state.attack_editor_version += 1
                st.rerun()

        attack_set_name = st.text_input("Attack set name", key="attack_set_name", placeholder="e.g. Finance support red team")
        editor_text = st.text_area(
            "Attack prompts editor",
            value=st.session_state.attack_editor_text,
            key=f"attack_editor_widget_{st.session_state.attack_editor_version}",
            height=360,
            help="One prompt per line. You can freely edit, paste, delete, or reorder prompts here.",
        )
        if editor_text != st.session_state.attack_editor_text:
            st.session_state.attack_editor_text = editor_text
        st.caption(f"Current prompt count: {len(_prompt_lines(editor_text))}")
        _workspace_card_end()

    with right:
        _workspace_card_start("Prompt sources")
        st.subheader("Add built-in prompts")
        st.caption("Checking a pack appends its prompts to the editor. Unchecking removes those exact built-in prompts.")
        for pack in list_prompt_source_packs():
            key = f"pack_{pack.id}"
            previous = st.session_state.pack_checkbox_state.get(pack.id, False)
            pack_prompts = [case.prompt for case in pack.cases]
            st.checkbox(
                f"{pack.name} ({len(pack.cases)})",
                value=previous,
                key=key,
                on_change=_sync_attack_pack,
                args=(pack.id, pack_prompts),
            )

        st.subheader("AI generate")
        ai_available = ai_attack_generation_available()
        if not ai_available:
            st.info("Disabled: set AGENTSURFACE_AI_ATTACK_API_KEY at deploy time.")
        ai_count = st.number_input("How many attacks", min_value=1, max_value=20, value=5, disabled=not ai_available)
        ai_context = st.text_area(
            "Agent/app description",
            placeholder="Example: finance support agent with deposit/withdrawal tools",
            disabled=not ai_available,
        )
        if st.button("Generate and add to editor", disabled=not ai_available):
            try:
                with st.spinner("Generating attacks..."):
                    generated = generate_ai_attack_cases(ai_context, int(ai_count))
                st.session_state.attack_editor_text = _append_prompts(
                    st.session_state.attack_editor_text,
                    [case.prompt for case in generated],
                )
                st.session_state.attack_editor_version += 1
                st.rerun()
            except Exception as exc:
                st.error(f"AI generation failed: {exc}")
        _workspace_card_end()

    if st.button("Save attack set", type="primary"):
        try:
            attack_set_id = save_attack_set(st.session_state.attack_set_name, st.session_state.attack_editor_text)
            st.success(f"Saved attack set #{attack_set_id}: {st.session_state.attack_set_name}")
        except Exception as exc:
            st.error(f"Save failed: {exc}")

    st.subheader("Saved attack sets")
    saved = list_attack_sets()
    if saved:
        st.dataframe(saved, use_container_width=True)
    else:
        st.info("No saved attack sets yet.")


def _history_page() -> None:
    _page_intro("History", "Recent persisted runs with summaries and export payloads for quick audit review.")
    runs = list_runs()
    if not runs:
        st.info("No persisted runs yet. Run an attack set first.")
        return

    rows = []
    for row in runs:
        try:
            summary = json.loads(row["summary_json"])
        except Exception:
            summary = {}
        rows.append(
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "total": summary.get("total", ""),
                "failed": summary.get("failed", ""),
                "passed": summary.get("passed", ""),
                "risk_score": summary.get("risk_score", ""),
            }
        )

    stat_cols = st.columns(3)
    with stat_cols[0]:
        _metric_card("Stored runs", len(rows), "Last 50 shown")
    with stat_cols[1]:
        _metric_card("Latest failed", rows[0].get("failed", "—"), "Most recent run")
    with stat_cols[2]:
        _metric_card("Latest risk", rows[0].get("risk_score", "—"), "Most recent run")

    st.dataframe(rows, use_container_width=True, hide_index=True)
    selected_run_id = st.selectbox("Inspect run", [row["id"] for row in rows])
    selected = next(row for row in runs if row["id"] == selected_run_id)
    try:
        report = json.loads(selected["report_json"])
    except Exception:
        report = None

    if report:
        summary = report.get("summary", {})
        _page_intro(
            "Selected run report",
            "Failed = attack succeeded / security issue found. Passed = attack was blocked or no deterministic issue was detected.",
        )
        cols = st.columns(4)
        with cols[0]:
            _metric_card("Total attacks", summary.get("total", "—"), "Prompts executed")
        with cols[1]:
            _metric_card("Attacks succeeded", summary.get("failed", "—"), "Needs review / policy")
        with cols[2]:
            _metric_card("Attacks blocked", summary.get("passed", "—"), "No issue detected")
        with cols[3]:
            _metric_card("Risk score", summary.get("risk_score", "—"), "Max finding severity")

        raw_results = report.get("raw_results", [])
        overview_rows = []
        for index, item in enumerate(raw_results, start=1):
            finding = item.get("finding", {})
            test_case = item.get("test_case", {})
            call = item.get("call", {})
            output = item.get("output") or call.get("error") or ""
            failed = bool(finding.get("failed"))
            overview_rows.append(
                {
                    "#": index,
                    "status": "API error" if call.get("error") else ("Attack succeeded" if failed else "Attack blocked"),
                    "attack": test_case.get("name", ""),
                    "category": test_case.get("category", ""),
                    "risk": finding.get("risk_score", 0),
                    "failure_types": ", ".join(finding.get("failure_types", [])) or "—",
                    "http_status": call.get("status_code") or "—",
                    "response_preview": str(output).replace("\n", " ")[:220],
                }
            )
        st.subheader("Attack outcome table")
        st.dataframe(overview_rows, use_container_width=True, hide_index=True)

        st.subheader("Prompts and agent replies")
        for index, item in enumerate(raw_results, start=1):
            finding = item.get("finding", {})
            test_case = item.get("test_case", {})
            call = item.get("call", {})
            output = item.get("output") or call.get("error") or "<empty response>"
            failed = bool(finding.get("failed"))
            status = "API error" if call.get("error") else ("Attack succeeded" if failed else "Attack blocked")
            title = f"{index}. {status} · {test_case.get('name', '')} · risk {finding.get('risk_score', 0)}"
            with st.expander(title, expanded=failed):
                st.write("Attack prompt")
                st.code(test_case.get("prompt", ""))
                st.write("Agent reply / extracted output")
                st.code(str(output))
                st.write("Finding")
                st.json(finding)
                with st.expander("Raw HTTP evidence", expanded=False):
                    st.write("Masked request")
                    st.json(item.get("masked_request", {}))
                    st.write("Raw response")
                    st.json(item.get("raw_response", {}))

    with st.expander("Full JSON report", expanded=False):
        if report:
            st.json(report)
        else:
            st.code(selected["report_json"], language="json")
    with st.expander("Lobster Trap policy YAML", expanded=False):
        st.code(selected["lobster_trap_yaml"], language="yaml")


if "last_run" not in st.session_state:
    st.session_state.last_run = None
if "page" not in st.session_state:
    st.session_state.page = "Run"

if hasattr(st, "segmented_control"):
    st.segmented_control(
        "Workspace",
        ["Run", "Attack Sets", "History"],
        key="page",
        label_visibility="collapsed",
    )
else:
    nav_col_1, nav_col_2, nav_col_3, _ = st.columns([1, 1, 1, 3])
    with nav_col_1:
        if st.button("Run", use_container_width=True):
            st.session_state.page = "Run"
    with nav_col_2:
        if st.button("Attack Sets", use_container_width=True):
            st.session_state.page = "Attack Sets"
    with nav_col_3:
        if st.button("History", use_container_width=True):
            st.session_state.page = "History"

st.markdown("<div style='height: 10px'></div>", unsafe_allow_html=True)
if st.session_state.page == "Run":
    _run_page()
elif st.session_state.page == "Attack Sets":
    _attack_sets_page()
else:
    _history_page()
