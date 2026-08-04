import os, json, time
from datetime import datetime, timezone

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "decisions.jsonl")

# Fields we NEVER write to disk (secret hygiene).
_REDACT_KEYS = {"api_key", "POE_API_KEY", "authorization"}


def _ensure_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def _sanitize(d: dict) -> dict:
    return {k: v for k, v in d.items() if k not in _REDACT_KEYS}


def log_decision(request: dict, rule_verdict: str, rule_reasons: list,
                 llm_verdict: str, final_decision: str,
                 latency_ms: float, error: str = None):
    """Append one structured decision record as a JSON line. Never raises."""
    try:
        _ensure_dir()
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "request": _sanitize(request),
            "rule_verdict": rule_verdict,
            "rule_reasons": rule_reasons,
            "llm_verdict": llm_verdict,
            "final_decision": final_decision,
            "latency_ms": round(latency_ms, 1),
        }
        if error:
            record["error"] = error
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        # Logging must never break a payment decision.
        pass
