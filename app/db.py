from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path(os.environ.get("AGENTSURFACE_DB", "agentsurface.db"))


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                config_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                report_json TEXT NOT NULL,
                lobster_trap_yaml TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS test_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                test_case_id TEXT NOT NULL,
                test_case_json TEXT NOT NULL,
                call_json TEXT NOT NULL,
                finding_json TEXT NOT NULL,
                output TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES runs(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS attack_sets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                prompts_text TEXT NOT NULL,
                prompt_count INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def save_run(run: Any, db_path: str | Path = DEFAULT_DB_PATH) -> int:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO runs (created_at, config_json, summary_json, report_json, lobster_trap_yaml)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                run.created_at,
                run.config.model_dump_json(),
                run.summary.model_dump_json(),
                json.dumps(run.report, ensure_ascii=False),
                run.lobster_trap_yaml,
            ),
        )
        run_id = int(cursor.lastrowid)
        for result in run.results:
            conn.execute(
                """
                INSERT INTO test_results (run_id, test_case_id, test_case_json, call_json, finding_json, output)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    result.test_case.id,
                    result.test_case.model_dump_json(),
                    result.call.model_dump_json(),
                    result.finding.model_dump_json(),
                    result.output,
                ),
            )
        return run_id


def list_runs(db_path: str | Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 50").fetchall()
    return [dict(row) for row in rows]


def _prompt_count(prompts_text: str) -> int:
    return len([line for line in prompts_text.splitlines() if line.strip()])


def save_attack_set(name: str, prompts_text: str, db_path: str | Path = DEFAULT_DB_PATH) -> int:
    init_db(db_path)
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Attack set name is required")
    count = _prompt_count(prompts_text)
    if count == 0:
        raise ValueError("Attack set must contain at least one prompt")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO attack_sets (name, prompts_text, prompt_count)
            VALUES (?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                prompts_text = excluded.prompts_text,
                prompt_count = excluded.prompt_count,
                updated_at = CURRENT_TIMESTAMP
            """,
            (clean_name, prompts_text.strip(), count),
        )
        row = conn.execute("SELECT id FROM attack_sets WHERE name = ?", (clean_name,)).fetchone()
    return int(row[0])


def list_attack_sets(db_path: str | Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, name, prompt_count, created_at, updated_at
            FROM attack_sets
            ORDER BY updated_at DESC, id DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_attack_set(attack_set_id: int, db_path: str | Path = DEFAULT_DB_PATH) -> dict[str, Any]:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM attack_sets WHERE id = ?", (attack_set_id,)).fetchone()
    if row is None:
        raise KeyError(f"Unknown attack set '{attack_set_id}'")
    return dict(row)
