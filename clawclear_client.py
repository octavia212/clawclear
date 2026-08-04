"""ClawClear client-side guard.

The enforcement point. An agent must route every spend through `guarded_pay`,
which:
  1. Calls POST /check BEFORE any money moves.
  2. Raises PaymentBlocked on `block`.
  3. Raises PaymentNeedsHuman on `needs-human` (escalate, do not send).
  4. On `allow`, receives a clearance_token BOUND to (destination, amount).
  5. Verifies the token locally (signature + binding + expiry) right before
     calling the payment rail, then passes the token to the rail so the rail
     can independently verify the spend was cleared.

A generic "was cleared" flag is worthless — the token is signed over
destination + amount + nonce + expiry, so it cannot be replayed for a
different destination or amount, and it goes stale in ~60s.
"""

import os
import requests

from clearance import verify_token, TokenInvalid, SigningSecretMissing

CLAWCLEAR_URL = os.environ.get("CLAWCLEAR_URL", "http://127.0.0.1:8000")
CHECK_TIMEOUT = 20  # seconds


class PaymentBlocked(Exception):
    """/check returned block — hard stop, do not send."""


class PaymentNeedsHuman(Exception):
    """/check returned needs-human — escalate to a person, do not send."""


class ClearanceError(Exception):
    """Could not obtain or verify a valid clearance token — fail closed."""


def _request_check(approved_task, approved_destinations, destination,
                   amount, recent_context):
    payload = {
        "approved_task": approved_task,
        "approved_destinations": approved_destinations or [],
        "destination": destination,
        "amount": amount,
        "recent_context": recent_context or "",
    }
    resp = requests.post(
        f"{CLAWCLEAR_URL}/check", json=payload, timeout=CHECK_TIMEOUT
    )
    resp.raise_for_status()
    return resp.json()


# --------------------------------------------------------------------------- #
# PAYMENT RAIL SEAM
# Replace the body of this function with the real x402 / MoltPay send call.
#
# HARD REQUIREMENTS for the real rail (NOT optional, NOT suggestions):
#
#   1. SERVER-SIDE RE-VERIFY IS THE ENFORCEMENT POINT.
#      The local verify_token() call in guarded_pay() below is a convenience
#      pre-check ONLY. It is NOT enforcement: an agent can bypass guarded_pay
#      entirely and call the rail directly. Therefore the rail MUST itself
#      re-verify the clearance token server-side (shared signing secret:
#      signature + destination + amount + expiry) before releasing ANY funds,
#      and MUST reject any payment that arrives without a valid token.
#
#   2. NONCE SINGLE-USE (anti double-send).
#      Binding stops a token being reused for a DIFFERENT payment, but nothing
#      here marks a token as spent — so the SAME token could be replayed for
#      the SAME destination+amount within its 60s window (double-send). The
#      rail MUST record each token's nonce as CONSUMED on first use and REJECT
#      any repeat nonce. Without a nonce store, replay-within-window is open.
#      When a server-side store exists, wire the check in right here (see the
#      stub below) before calling the SDK.
# --------------------------------------------------------------------------- #
def _rail_send(destination, amount, clearance_token, **kwargs):
    """Forward the payment to the rail's server-side enforcement path.

    The rail (rail.py) is THE enforcement point: it re-verifies the token
    server-side (sig + dest + amount + expiry) and atomically consumes the
    nonce (single-use, committed before funds release). This client does not
    and cannot enforce those guarantees — an agent can bypass this function
    entirely, so the rail never trusts it.
    """
    from rail import pay, RailRejected
    try:
        return pay(destination, amount, clearance_token, **kwargs)
    except RailRejected as e:
        # Rail refused (missing/bad/expired token, or nonce double-send).
        raise ClearanceError(f"rail rejected payment: {e}")


def guarded_pay(destination, amount, approved_task,
                approved_destinations=None, recent_context="", **rail_kwargs):
    """Check-then-send. The only sanctioned path for an agent to spend.

    Raises PaymentBlocked / PaymentNeedsHuman / ClearanceError instead of
    ever sending an unverified payment.
    """
    result = _request_check(
        approved_task, approved_destinations, destination, amount, recent_context
    )
    decision = result.get("decision")
    reasons = result.get("reasons", [])

    if decision == "block":
        raise PaymentBlocked(f"payment blocked: {reasons}")
    if decision == "needs-human":
        raise PaymentNeedsHuman(f"needs human approval: {reasons}")
    if decision != "allow":
        raise ClearanceError(f"unexpected decision '{decision}': {reasons}")

    token = result.get("clearance_token")
    if not token:
        # allow with no token = server couldn't sign (e.g. missing secret).
        raise ClearanceError("allowed but no clearance token issued; failing closed")

    # Verify the token locally right before sending: signature + that it is
    # bound to THIS destination+amount + not expired. verify_token raises on
    # any failure (and SigningSecretMissing if no secret is configured).
    try:
        verify_token(token, destination, amount)
    except TokenInvalid as e:
        raise ClearanceError(f"clearance token invalid: {e}")
    except SigningSecretMissing as e:
        raise ClearanceError(f"cannot verify clearance token: {e}")

    # Cleared and verified — release funds through the rail seam.
    return _rail_send(destination, amount, token, **rail_kwargs)
