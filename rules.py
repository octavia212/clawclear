import os, re, json, time, unicodedata
from datetime import datetime, timezone

try:
    import yaml
except ImportError:
    yaml = None

_HERE = os.path.dirname(os.path.abspath(__file__))
_CONFIG_PATH = os.path.join(_HERE, "patterns.yaml")
_LOG_FILE = os.path.join(_HERE, "logs", "decisions.jsonl")

# Conservative fallback if config can't be read. Fail toward caution.
_FALLBACK = {
    "limits": {
        "per_tx_max": 100.0,
        "velocity_window_seconds": 3600,
        "velocity_max_total": 500.0,
    },
    "injection_patterns": [
        r"ignore (all|any|previous|prior|the above) instructions",
        r"send (all|everything|the funds|the money) to",
        r"bypass",
    ],
}


def load_config():
    """Load patterns.yaml. On any failure, return the conservative fallback."""
    if yaml is None:
        return _FALLBACK
    try:
        with open(_CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
        # Merge missing keys from fallback so a partial file can't break us.
        limits = {**_FALLBACK["limits"], **(cfg.get("limits") or {})}
        patterns = cfg.get("injection_patterns") or _FALLBACK["injection_patterns"]
        return {"limits": limits, "injection_patterns": patterns}
    except Exception:
        return _FALLBACK


def _normalize(text: str) -> str:
    """Fold unicode tricks + collapse whitespace so patterns can't be evaded."""
    if not text:
        return ""
    # NFKC folds homoglyphs/fullwidth; strip zero-width & control chars.
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C" or ch in " \t\n")
    text = re.sub(r"\s+", " ", text)
    return text.lower()


def _compile(patterns):
    compiled = []
    for pat in patterns:
        try:
            compiled.append((pat, re.compile(pat, re.IGNORECASE)))
        except re.error:
            # A malformed pattern shouldn't kill the engine; skip it.
            continue
    return compiled


def check_injection(context: str, patterns):
    """Return list of matched pattern strings (empty = clean)."""
    norm = _normalize(context)
    hits = []
    for raw, rx in _compile(patterns):
        if rx.search(norm):
            hits.append(raw)
    return hits


def _velocity_total(destination: str, window_seconds: int):
    """Sum of ALLOWED amounts within the window.

    Returns (total, ok). ok=False means the log was unreadable/corrupt in a way
    we couldn't safely interpret -> caller must fail to needs-human, never allow.
    """
    now = time.time()
    cutoff = now - window_seconds
    total = 0.0
    saw_malformed = False

    if not os.path.exists(_LOG_FILE):
        # No history yet is a VALID state (fresh service) -> total 0, ok.
        return 0.0, True

    try:
        with open(_LOG_FILE) as f:
            lines = f.readlines()
    except Exception:
        # Log exists but can't be read -> unsafe to assume zero spend.
        return 0.0, False

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            if rec.get("final_decision") != "allow":
                continue
            ts = datetime.fromisoformat(rec["ts"]).timestamp()
            if ts < cutoff:
                continue
            amt = float(rec["request"]["amount"])
            total += amt
        except Exception:
            # A single bad line shouldn't crash us, but note it so we can
            # fail cautious rather than silently undercount spend.
            saw_malformed = True
            continue

    return total, (not saw_malformed)


def amount_checks(destination: str, amount: float, limits: dict):
    """Return (verdict, reasons). verdict in allow|needs-human.

    Never returns 'allow' when velocity state is unknown -> fail to needs-human.
    """
    reasons = []
    per_tx = float(limits.get("per_tx_max", _FALLBACK["limits"]["per_tx_max"]))
    window = int(limits.get("velocity_window_seconds", 3600))
    vmax = float(limits.get("velocity_max_total", _FALLBACK["limits"]["velocity_max_total"]))

    if amount > per_tx:
        reasons.append(f"amount {amount} exceeds per-tx max {per_tx}")
        return "needs-human", reasons

    total, ok = _velocity_total(destination, window)
    if not ok:
        reasons.append("velocity log unreadable/corrupt -> failing to needs-human")
        return "needs-human", reasons

    if total + amount > vmax:
        reasons.append(
            f"velocity: {total}+{amount} over {vmax} in last {window}s"
        )
        return "needs-human", reasons

    return "allow", reasons
