from __future__ import annotations

import yaml

INGRESS_RULES = {
    "instruction_override_compliance": {
        "name": "block_prompt_injection",
        "description": "Detected prompt injection attempt",
        "priority": 100,
        "action": "DENY",
        "deny_message": "[LOBSTER TRAP] Blocked: prompt injection detected.",
        "conditions": [{"field": "contains_injection_patterns", "match_type": "boolean", "value": True}],
    },
    "dangerous_action_compliance": {
        "name": "block_dangerous_commands",
        "description": "Dangerous system commands detected",
        "priority": 80,
        "action": "DENY",
        "deny_message": "[LOBSTER TRAP] Blocked: dangerous command detected.",
        "conditions": [
            {"field": "contains_system_commands", "match_type": "boolean", "value": True},
            {"field": "risk_score", "match_type": "threshold", "value": 0.3},
        ],
    },
    "unsafe_content_compliance": {
        "name": "review_high_risk",
        "description": "High risk score requires human review",
        "priority": 70,
        "action": "HUMAN_REVIEW",
        "conditions": [{"field": "risk_score", "match_type": "threshold", "value": 0.6}],
    },
    "cross_user_data_disclosure": {
        "name": "block_cross_user_data_access",
        "description": "Prompt attempts to access another authenticated user's account data",
        "priority": 96,
        "action": "DENY",
        "deny_message": "[LOBSTER TRAP] Blocked: cross-user account data access detected.",
        "conditions": [{"field": "cross_user_data_access", "match_type": "boolean", "value": True}],
    },
}

UNSUPPORTED_RUNTIME_SIGNALS = {
    "cross_user_data_disclosure": {
        "signal": "cross_user_data_access",
        "limitation": (
            "cross_user_data_disclosure requires application/tool-layer authorization "
            "or a custom Lobster Trap runtime signal; it is not a native prompt metadata field."
        ),
    },
}

EGRESS_RULES = {
    "secret_disclosure": {
        "name": "block_credential_leak",
        "description": "Model output contains credentials",
        "priority": 100,
        "action": "DENY",
        "deny_message": "[LOBSTER TRAP] Output blocked: contains credentials.",
        "conditions": [{"field": "contains_credentials", "match_type": "boolean", "value": True}],
    },
    "system_prompt_disclosure": {
        "name": "block_system_prompt_disclosure",
        "description": "Model output appears to disclose system, developer, or hidden instructions",
        "priority": 95,
        "action": "DENY",
        "deny_message": "[LOBSTER TRAP] Output blocked: system prompt disclosure detected.",
        "conditions": [{"field": "contains_injection_patterns", "match_type": "boolean", "value": True}],
    },
    "api_error": {
        "name": "log_agent_api_adapter_errors",
        "description": "AgentSurface observed adapter/API errors; inspect config before enforcing policy",
        "priority": 10,
        "action": "LOG",
        "conditions": [{"field": "risk_score", "match_type": "threshold", "value": 0.1}],
    },
}

BASE_INGRESS_RULES = {
    "block_sensitive_paths": {
        "name": "block_sensitive_paths",
        "description": "Prompt targets sensitive system paths",
        "priority": 85,
        "action": "DENY",
        "deny_message": "[LOBSTER TRAP] Blocked: sensitive path access denied.",
        "conditions": [{"field": "contains_sensitive_paths", "match_type": "boolean", "value": True}],
    },
    "block_data_exfiltration": {
        "name": "block_data_exfiltration",
        "description": "Prompt contains data exfiltration patterns",
        "priority": 92,
        "action": "DENY",
        "deny_message": "[LOBSTER TRAP] Blocked: data exfiltration attempt detected.",
        "conditions": [{"field": "contains_exfiltration", "match_type": "boolean", "value": True}],
    },
}

BASE_EGRESS_RULES = {
    "block_pii_leak": {
        "name": "block_pii_leak",
        "description": "Model output contains PII",
        "priority": 90,
        "action": "DENY",
        "deny_message": "[LOBSTER TRAP] Output blocked: contains PII.",
        "conditions": [{"field": "contains_pii", "match_type": "boolean", "value": True}],
    }
}


def _ordered_unique_rules(rules: list[dict]) -> list[dict]:
    by_name = {rule["name"]: rule for rule in rules}
    return sorted(by_name.values(), key=lambda rule: (-rule["priority"], rule["name"]))


def generate_lobster_trap_yaml(failures: list[str], risk_score: int) -> str:
    """Generate a veeainc/lobstertrap-compatible policy YAML draft.

    Lobster Trap is an OpenAI-compatible reverse proxy. AgentSurface produces this
    as a deployable policy draft for LLM traffic protected by that proxy.
    """
    ingress_rules: list[dict] = []
    egress_rules: list[dict] = []
    unsupported_signals: list[str] = []
    limitations: list[str] = []

    for failure in failures:
        if failure in UNSUPPORTED_RUNTIME_SIGNALS:
            unsupported = UNSUPPORTED_RUNTIME_SIGNALS[failure]
            unsupported_signals.append(unsupported["signal"])
            limitations.append(unsupported["limitation"])
            continue
        if failure in INGRESS_RULES:
            ingress_rules.append(INGRESS_RULES[failure])
        if failure in EGRESS_RULES:
            egress_rules.append(EGRESS_RULES[failure])

    if "secret_disclosure" in failures:
        ingress_rules.append(BASE_INGRESS_RULES["block_data_exfiltration"])
    if "system_prompt_disclosure" in failures:
        ingress_rules.append(INGRESS_RULES["instruction_override_compliance"])
    if risk_score >= 70 and "unsafe_content_compliance" not in failures:
        ingress_rules.append(INGRESS_RULES["unsafe_content_compliance"])
    if not ingress_rules and not egress_rules:
        ingress_rules.append(INGRESS_RULES["instruction_override_compliance"])

    if egress_rules:
        egress_rules.append(BASE_EGRESS_RULES["block_pii_leak"])
    if ingress_rules:
        ingress_rules.append(BASE_INGRESS_RULES["block_sensitive_paths"])

    data = {
        "version": "1.0",
        "policy_name": "agentsurface-generated",
        "default_action": "ALLOW",
        "metadata": {
            "source": "AgentSurface",
            "target": "veeainc/lobstertrap",
            "risk_score": risk_score,
            "deployable": not unsupported_signals,
            "unsupported_signals": list(dict.fromkeys(unsupported_signals)),
            "limitations": list(dict.fromkeys(limitations)),
            "note": "Deploy with: lobstertrap serve --policy agentsurface_policy.yaml --backend <openai-compatible-backend>",
        },
        "ingress_rules": _ordered_unique_rules(ingress_rules),
        "egress_rules": _ordered_unique_rules(egress_rules),
        "rate_limits": {
            "requests_per_minute": 120,
            "requests_per_hour": 2000,
            "burst_threshold": 30,
        },
        "network": {
            "egress_policy": "allowlist",
            "allowed_domains": ["api.openai.com", "api.anthropic.com"],
            "denied_domains": ["*.onion", "pastebin.com"],
        },
        "filesystem": {
            "denied_paths": ["/etc/**", "/root/**", "**/.ssh/**", "**/.env", "**/*secret*", "**/*password*"],
            "allowed_read_paths": ["/tmp/agent_workspace/**"],
            "allowed_write_paths": ["/tmp/agent_workspace/**"],
        },
    }
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
