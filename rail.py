"""ClawClear payment rail — SERVER-SIDE ENFORCEMENT POINT.

This module is the real gate. It does NOT trust the client. An agent can
bypass `guarded_pay` and call a rail directly, so every guarantee lives here:

  1. SERVER-SIDE RE-VERIFY (the enforcement point).
     `pay()` re-runs verify_token itself (signature + destination + amount +
     expiry, via the shared signing secret). A payment with no token, or a
     bad/expired/mis-bound token, is rejected before any funds move. The
     client-side verify_token in guarded_pay is advisory only.

  2. NONCE SINGLE-USE (anti double-send).
     Consuming a nonce is a SINGLE atomic check-and-consume: "is it used?" and
     "mark it used" happen in one lock-guarded step that cannot be split into
     two separate calls. The consume COMMITS BEFORE funds are released, so two
     concurrent requests carrying the same nonce can never both pass — exactly
     one wins, the other is rejected.

Scope for now (per decision): ONE process, in-memory used-nonce set + lock.
Expiry (60s) already voids any pre-crash ticket, so a sub-60s restart is the
only theoretical exposure and is not a real risk pre-real-money.

KNOWN FOLLOW-UP (when real money is gated): swap `_InMemoryNonceStore` for a
durable store (SQLite, UNIQUE on nonce) so used tickets survive a crash and we
can prove no double-spend across restarts. The consume seam is deliberately
narrow — only `NonceStore.check_and_consume` and the store construction change.
"""

import threading

from clearance import verify_token, TokenInvalid, SigningSecretMissing


class RailRejected(Exception):
    """The rail refused to release funds. Fail closed. Reasons:
    missing/invalid/expired token, or a nonce already consumed (double-send)."""


class NonceStore:
    """Interface for the used-nonce store. The ONE seam to swap for a durable
    backend (SQLite UNIQUE) later. Implementations MUST make check_and_consume
    a single atomic operation."""

    def check_and_consume(self, nonce: str) -> bool:
        raise NotImplementedError


class _InMemoryNonceStore(NonceStore):
    """In-memory single-use nonce set guarded by a lock.

    check_and_consume is the atomic primitive: under the lock it checks
    membership and inserts in one indivisible step, then returns whether THIS
    caller won the nonce. No separate is_used()/consume() calls exist, so there
    is no window between the check and the mark for a second thread to slip in.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._used = set()

    def check_and_consume(self, nonce: str) -> bool:
        # Single atomic check-and-consume. Returns True if the nonce was fresh
        # and is now consumed by this caller; False if it was already consumed.
        with self._lock:
            if nonce in self._used:
                return False
            self._used.add(nonce)
            return True


# Process-wide store (one process, per current scope).
_nonce_store: NonceStore = _InMemoryNonceStore()


def _sdk_release_funds(destination, amount, **kwargs):
    """MOCK x402 / MoltPay send. Replace this body with the real SDK call.

    By the time we get here the token is re-verified AND its nonce is already
    committed as consumed, so this is the only place real money moves.

    KNOWN FOLLOW-UP (real-SDK time) — funds-release FAILURE HANDLING:
    The nonce is already burned before we reach here, so a failure here must
    NOT die silently. Rule: SHOUT → VERIFY → RETRY-WITH-FRESH-NONCE-ONLY.
      1. FAIL LOUD. Surface the error clearly; never let a legit payment die
         quietly.
      2. DO NOT blind-retry. A lost success-reply looks identical to a real
         failure — blind retry there = double-pay, the exact thing we prevent.
         First check whether the payment actually went through via the real
         SDK's status-check / idempotency key.
      3. ONLY if confirmed NOT sent, retry with a FRESH token/nonce — never
         the burned one (it's consumed and would be rejected anyway).
    The status-check mechanism depends on the real SDK, so this is parked until
    the SDK is wired.
    """
    return {
        "status": "sent",
        "mock": True,
        "destination": destination,
        "amount": amount,
    }


def pay(destination, amount, clearance_token, store: NonceStore = None, **kwargs):
    """THE enforcement path. Re-verify server-side, atomically consume the
    nonce, THEN release funds. Raises RailRejected on any failure.

    Order is deliberate:
      (a) re-verify token (sig + dest + amount + expiry) — reject if bad/missing
      (b) atomic check-and-consume nonce — reject if already used (double-send)
      (c) release funds — only after the consume has COMMITTED
    """
    store = store or _nonce_store

    # (a) Server-side re-verify. Never trust that the caller pre-checked.
    if not clearance_token:
        raise RailRejected("no clearance token presented")
    try:
        payload = verify_token(clearance_token, destination, amount)
    except TokenInvalid as e:
        raise RailRejected(f"token failed server-side verify: {e}")
    except SigningSecretMissing as e:
        raise RailRejected(f"cannot verify token (no signing secret): {e}")

    nonce = payload.get("nonce")
    if not nonce:
        raise RailRejected("verified token carries no nonce")

    # (b) Atomic single-use consume, COMMITTED BEFORE funds move.
    if not store.check_and_consume(nonce):
        raise RailRejected(f"nonce {nonce} already consumed (double-send rejected)")

    # (c) Cleared, verified, nonce committed -> release funds.
    receipt = _sdk_release_funds(destination, amount, **kwargs)
    receipt["nonce"] = nonce
    return receipt
