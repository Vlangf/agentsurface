# AgentSurface

![AgentSurface cover](assets/cover.png)

AgentSurface is a security testing workspace for real AI agents exposed as HTTP JSON APIs. It sends adversarial prompts to an existing agent endpoint, captures the real request/response evidence, evaluates whether the response contains a security failure, and stores an auditable report.

It is built for testing support bots, finance assistants, trading assistants, CRM agents, marketplace agents, and other tool-using AI systems where the biggest risks are often business-logic failures rather than generic jailbreaks.

## What AgentSurface tests

AgentSurface helps find issues such as:

- prompt injection and instruction override compliance
- secret, credential, or system-prompt disclosure
- unsafe tool/action compliance
- private data exposure in raw or extracted responses
- BOLA/IDOR-style cross-user data access
- support-agent authorization gaps around profile, KYC, balances, withdrawals, transactions, and account state

The target is always your real agent API. AgentSurface does not require a mock server or special SDK integration.

## How it works

1. Build or generate an attack set.
2. Configure the target HTTP endpoint, headers, request template, and prompt input path.
3. AgentSurface injects each prompt into the request JSON.
4. The real agent API is called through `httpx`.
5. Sensitive request headers are masked before storage/display.
6. The full raw response and extracted answer are evaluated.
7. Findings are saved to SQLite with risk score, evidence, and recommendations.
8. Reports can be reviewed in the UI or exported as JSON.
9. A Lobster Trap policy draft can be exported for proxy-layer mitigations when applicable.

## Interface

The Streamlit UI has three main workspaces:

- `Attack Sets` — create reusable adversarial prompt sets, one prompt per line.
- `Run` — select a saved attack set, configure the real agent API, and launch a scan.
- `History` — review previous runs, raw evidence, findings, exports, and policy drafts.

## Key features

- Real HTTP JSON adapter for existing AI agent APIs
- Request template injection with dot-path input selection
- Automatic response extraction from common fields like `answer`, `reply`, `response`, `output`, `text`, `content`, and OpenAI-style `choices.0.message.content`
- Full raw-response evaluation so hidden leaks in metadata/debug fields are not ignored
- Built-in attack packs for prompt injection, data exfiltration, tool misuse, and jailbreak testing
- AI attack generation when `AGENTSURFACE_AI_ATTACK_API_KEY` is configured
- LLM response judge enabled automatically when the same API key is configured
- SQLite persistence for attack sets, runs, and test results
- Masking for Authorization, API keys, tokens, cookies, and secret-like headers
- JSON report export
- Lobster Trap YAML policy draft export

## Stack

- Python
- FastAPI
- Streamlit
- Pydantic
- httpx
- SQLite
- Docker Compose
- uv

## Run with Docker

```bash
docker compose up --build
```

Open:

- Frontend: http://127.0.0.1:8501
- Backend: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs

Both services share SQLite data through the `agentsurface-data` Docker volume at `/data/agentsurface.db`.

## Run locally

Install dependencies:

```bash
uv sync --extra test
```

Start the backend:

```bash
uv run uvicorn app.main:app --reload
```

Start the UI:

```bash
uv run streamlit run ui/streamlit_app.py
```

## Configuration

AI-generated attack prompts and semantic response judging use an OpenAI-compatible chat completions endpoint.

```bash
export AGENTSURFACE_AI_ATTACK_API_KEY=...
export AGENTSURFACE_AI_ATTACK_BASE_URL=https://api.openai.com/v1   # optional
export AGENTSURFACE_AI_ATTACK_MODEL=gpt-4o-mini                    # optional
```

If `AGENTSURFACE_AI_ATTACK_API_KEY` is not set:

- AI attack generation is disabled.
- LLM semantic response judging is disabled.
- Deterministic evaluators still run.

If the key is set, semantic response judging is part of the normal run flow.

## Adapter configuration

AgentSurface sends requests according to your adapter settings:

- `endpoint_url` — target agent endpoint
- `method` — HTTP method
- `headers` — request headers, with sensitive values masked in stored evidence
- `request_template` — JSON body template
- `input_path` — dot path where the attack prompt should be inserted
- `timeout_seconds` — per-request timeout

Example request template:

```json
{
  "user_id": "u_1001",
  "message": "{{input}}"
}
```

Example input path:

```text
message
```

When AgentSurface runs an attack set, each prompt replaces `{{input}}` and is sent to the real endpoint.

## Docker-to-host target URLs

When AgentSurface runs in Docker and the target test app runs on the host machine, use Docker Desktop's host gateway:

```text
http://host.docker.internal:<port>/<path>
```

Example:

```text
http://host.docker.internal:8043/chat
```

If you open the same target directly from macOS, use:

```text
http://127.0.0.1:8043/chat
```

## API endpoints

- `GET /health`
- `GET /test-packs`
- `POST /runs`
- `GET /runs`
- `POST /reports/json`
- `POST /lobster-trap.yaml`

## Lobster Trap policy export

AgentSurface can generate a `veeainc/lobstertrap`-compatible YAML policy draft from detected failure types.

```bash
lobstertrap serve --policy agentsurface_policy.yaml --backend http://your-openai-compatible-llm-backend
```

Traffic shape:

```text
agent/app -> lobstertrap -> LLM backend
```

Important: not every finding can be fully enforced at the proxy layer. Business-logic findings such as cross-user data exposure often require application/tool-layer authorization checks. In those cases, the exported policy marks unsupported runtime signals instead of pretending that a proxy-only rule is sufficient.

## Development checks

```bash
uv run pytest -q
```

## Suggested repository metadata

Repository name:

```text
agentsurface
```

Short GitHub description:

```text
Security testing workspace for real AI agents exposed as HTTP JSON APIs.
```
