# ClawClear

A pre-spend intent check for AI-agent payments on x402 / MoltPay. Before an
agent moves money, it asks ClawClear and gets back **allow / block / needs-human**.
On `allow`, ClawClear mints a short-lived **clearance token bound to that exact
payment** (destination + amount + nonce + expiry) so the payment rail can prove
the spend was actually cleared.
## Live
https://buy.stripe.com/00waEWgDyfAj7UQdaX08g00
Production: https://web-production-aff0b.up.railway.app

- Health: `GET /` returns `{"status":"ClawClear running"}`
- Check: `POST /check`

This does not move money. It is a pre-spend decision layer.

'''bash
curl -s -X POST https://web-production-aff0b.up.railway.app/check -H 'content-type: application/json' -d '{'''
  "approved_task":"pay the monthly AWS hosting invoice",
  "approved_destinations":["0xAWS"],
  "destination":"0xAWS",
  "amount":10,
  "recent_context":"routine monthly cloud hosting bill"
}'
## Architecture

Two-layer decision, cheap gate first:

1. **Rule layer** (`rules.py`, config in `patterns.yaml`) — deterministic:
   - destination allow-list (normalized case/whitespace)
   - prompt-injection / coercion regex scan over a **unicode-normalized** copy
     of the context (defeats zero-width chars + homoglyphs)
   - per-tx amount ceiling + rolling velocity window (reads `logs/decisions.jsonl`)
2. **LLM layer** (`app.py` → litellm → poe.com, `gpt-4o-mini`) — only runs if
   the rules pass; judges task drift / coercion. Fails **cautious**
   (`needs-human`) on any error or ambiguity, never `allow`.

Every decision is appended to `logs/decisions.jsonl` (`logger.py`), with secrets
redacted.

Enforcement is client-side: agents must route spends through
`guarded_pay()` in `clawclear_client.py`, which calls `/check`, honors the
verdict, and only calls the payment rail after locally verifying the clearance
token.

## Files

| file | role |
|---|---|
| `app.py` | FastAPI service: `GET /` health, `POST /check` |
| `rules.py` | rule engine (config load, normalize, injection, amount/velocity) |
| `patterns.yaml` | tunable limits + injection patterns (no code edits to tune) |
| `clearance.py` | signed, payment-bound clearance tokens |
| `logger.py` | JSONL decision log (secret-redacted) |
| `clawclear_client.py` | `guarded_pay()` guard + mock rail seam |
| `test_clawclear.py` | reproducible test suite |

## Environment variables

| var | required | purpose |
|---|---|---|
| `POE_API_KEY` | for the LLM layer | poe.com key for `gpt-4o-mini` judgment |
| `CLAWCLEAR_SIGNING_SECRET` | **yes** | HMAC secret for clearance tokens |
| `CLAWCLEAR_URL` | no | client target, default `http://127.0.0.1:8000` |

**Fail-closed:** if `CLAWCLEAR_SIGNING_SECRET` is not set, ClawClear **refuses
to issue clearance tokens** and downgrades an otherwise-`allow` decision to
`needs-human`. There is no unsigned fallback. The secret is read from env only,
never hardcoded, and is never logged.

## Run the server

```bash
cd ~/clawclear
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt   # first time

export POE_API_KEY="…"                    # for the LLM layer
export CLAWCLEAR_SIGNING_SECRET="…"        # required, or token issuance fails closed
./venv/bin/uvicorn app:app --port 8000
```

Health check: `curl http://127.0.0.1:8000/`

Example check:

```bash
curl -s -X POST http://127.0.0.1:8000/check -H 'content-type: application/json' -d '{
  "approved_task":"pay the monthly AWS hosting invoice",
  "approved_destinations":["0xAWS"],
  "destination":"0xAWS",
  "amount":10,
  "recent_context":"routine monthly cloud hosting bill"
}'
```

On `allow` the response includes `clearance_token` and `token_exp`.

## Tune the rules

Edit `patterns.yaml` — no code changes:

```yaml
limits:
  per_tx_max: 100.0            # single tx above this -> needs-human
  velocity_window_seconds: 3600
  velocity_max_total: 500.0    # window total above this -> needs-human
injection_patterns:
  - "…regex…"                  # case-insensitive, run on normalized text
```

A missing/corrupt/partial file falls back to conservative built-in defaults.

## ⚠️ HARD RAIL REQUIREMENTS (read before wiring a real SDK)

The mock rail (`_rail_send` in `clawclear_client.py`) is **advisory only**. The
security guarantees below do **not** exist until the real x402 / MoltPay rail
enforces them server-side. Do not treat ClawClear as protecting funds until both
are implemented.

1. **Server-side re-verify is THE enforcement point.**
   The local `verify_token()` in `guarded_pay()` is a convenience pre-check
   only. An agent can bypass `guarded_pay` and call the rail directly, so the
   **rail itself MUST re-verify** every clearance token server-side (signature +
   destination + amount + expiry, shared signing secret) and **reject any
   payment that arrives without a valid token.**

2. **Nonce single-use (anti double-send).**
   Token binding stops reuse for a *different* payment, but nothing marks a
   token *spent* — so the same token could be replayed for the *same*
   destination+amount within its 60s window. The rail **MUST record each token's
   nonce as consumed on first use and reject any repeat nonce.** Mark the nonce
   consumed **atomically before releasing funds.**

Both requirements are also stated in the `_rail_send` seam comment, with a
wire-in stub, so they can't be missed at SDK-integration time.

## Tests

```bash
export CLAWCLEAR_SIGNING_SECRET="test-secret"   # test suite sets its own if unset
./venv/bin/python test_clawclear.py
```

The suite runs offline (no LLM / no network) and covers: bad destination →
block, injection incl. zero-width + homoglyph → block, over per-tx limit →
needs-human, velocity → needs-human, token replay to different dest/amount →
rejected, and missing signing secret → fail closed.
