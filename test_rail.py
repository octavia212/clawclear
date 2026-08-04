#!/usr/bin/env python3
"""ClawClear rail enforcement tests — OFFLINE, no network, no LLM.

Proves the two hard requirements against the MOCK rail:

  1. SERVER-SIDE RE-VERIFY is the enforcement point (rail.pay re-verifies the
     token itself and rejects missing / bad-sig / wrong-dest / wrong-amount /
     expired tokens, regardless of what any client did).

  2. NONCE SINGLE-USE via an atomic check-and-consume, committed before funds
     release. Includes a REAL threaded race: the same nonce fired from two
     threads at the same instant, proving exactly ONE succeeds.

Run:
    export CLAWCLEAR_SIGNING_SECRET="test-secret"   # auto-set below if unset
    ./venv/bin/python test_rail.py

Exit code 0 = all pass, 1 = failure.
"""

import os, sys, time, threading

os.environ.setdefault("CLAWCLEAR_SIGNING_SECRET", "test-secret")

import clearance
import rail
from rail import pay, RailRejected, _InMemoryNonceStore

_PASS, _FAIL = 0, 0


def check(name, condition, detail=""):
    global _PASS, _FAIL
    mark = "PASS" if condition else "FAIL"
    if condition:
        _PASS += 1
    else:
        _FAIL += 1
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail else ""))


def _tok(dest, amount, ttl=60):
    return clearance.issue_token(dest, amount, ttl=ttl)["token"]


# --------------------------------------------------------------------------- #
# 1. Server-side re-verify is the enforcement point
# --------------------------------------------------------------------------- #
def test_reverify():
    print("\n== server-side re-verify (enforcement point) ==")
    store = _InMemoryNonceStore()

    # valid token -> funds release
    ok = True
    try:
        r = pay("0xaws", 10.0, _tok("0xaws", 10.0), store=store)
        ok = r["status"] == "sent"
    except RailRejected as e:
        ok = False
    check("valid token -> funds released", ok)

    # no token -> rejected
    try:
        pay("0xaws", 10.0, None, store=store)
        check("missing token -> rejected", False, "released (bad!)")
    except RailRejected as e:
        check("missing token -> rejected", True, str(e))

    # empty-string token -> rejected
    try:
        pay("0xaws", 10.0, "", store=store)
        check("empty token -> rejected", False, "released (bad!)")
    except RailRejected as e:
        check("empty token -> rejected", True, str(e))

    # garbage token -> rejected
    try:
        pay("0xaws", 10.0, "not.a.real.token", store=store)
        check("malformed token -> rejected", False, "released (bad!)")
    except RailRejected as e:
        check("malformed token -> rejected", True, str(e))

    # token bound to a DIFFERENT destination -> rejected (rail re-verifies)
    try:
        pay("0xEVIL", 10.0, _tok("0xaws", 10.0), store=store)
        check("wrong destination -> rejected", False, "released (bad!)")
    except RailRejected as e:
        check("wrong destination -> rejected", True, str(e))

    # token bound to a DIFFERENT amount -> rejected
    try:
        pay("0xaws", 9999.0, _tok("0xaws", 10.0), store=store)
        check("wrong amount -> rejected", False, "released (bad!)")
    except RailRejected as e:
        check("wrong amount -> rejected", True, str(e))

    # tampered signature -> rejected
    good = _tok("0xaws", 10.0)
    body, sig = good.split(".", 1)
    tampered = body + "." + ("A" * len(sig))
    try:
        pay("0xaws", 10.0, tampered, store=store)
        check("tampered signature -> rejected", False, "released (bad!)")
    except RailRejected as e:
        check("tampered signature -> rejected", True, str(e))

    # expired token -> rejected (issue with ttl=1, wait it out)
    expiring = _tok("0xaws", 10.0, ttl=1)
    time.sleep(1.2)
    try:
        pay("0xaws", 10.0, expiring, store=store)
        check("expired token -> rejected", False, "released (bad!)")
    except RailRejected as e:
        check("expired token -> rejected", True, str(e))


# --------------------------------------------------------------------------- #
# 2. Nonce single-use (sequential sanity)
# --------------------------------------------------------------------------- #
def test_nonce_replay_sequential():
    print("\n== nonce single-use (sequential) ==")
    store = _InMemoryNonceStore()
    token = _tok("0xaws", 10.0)

    r = pay("0xaws", 10.0, token, store=store)
    check("first use of nonce -> released", r["status"] == "sent")

    try:
        pay("0xaws", 10.0, token, store=store)
        check("replay same nonce -> rejected", False, "released twice (bad!)")
    except RailRejected as e:
        check("replay same nonce -> rejected", True, str(e))


# --------------------------------------------------------------------------- #
# 3. CONCURRENT double-send — the real race
#    Same nonce fired from two threads at the same instant. Exactly one must
#    succeed; the other must be rejected. Sequential tests don't prove this.
# --------------------------------------------------------------------------- #
def test_nonce_concurrent_race():
    print("\n== nonce single-use (CONCURRENT race) ==")
    store = _InMemoryNonceStore()
    token = _tok("0xaws", 10.0)

    results = []
    results_lock = threading.Lock()
    start_barrier = threading.Barrier(2)

    def worker():
        # Barrier makes both threads hit check_and_consume as close to the
        # same instant as the scheduler allows -> a genuine race.
        start_barrier.wait()
        try:
            r = pay("0xaws", 10.0, token, store=store)
            with results_lock:
                results.append(("ok", r))
        except RailRejected as e:
            with results_lock:
                results.append(("rejected", str(e)))

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start(); t2.start()
    t1.join(); t2.join()

    oks = [r for r in results if r[0] == "ok"]
    rejected = [r for r in results if r[0] == "rejected"]

    check("concurrent: exactly ONE succeeded", len(oks) == 1,
          f"{len(oks)} ok / {len(rejected)} rejected")
    check("concurrent: exactly ONE rejected", len(rejected) == 1,
          f"{len(oks)} ok / {len(rejected)} rejected")


def test_nonce_concurrent_race_stress():
    print("\n== nonce single-use (CONCURRENT race, repeated) ==")
    # Repeat the race many times with fresh nonces. If atomicity were broken,
    # a double-release would surface across enough trials.
    trials = 200
    double_releases = 0
    zero_releases = 0
    for _ in range(trials):
        store = _InMemoryNonceStore()
        token = _tok("0xaws", 10.0)
        results = []
        results_lock = threading.Lock()
        barrier = threading.Barrier(2)

        def worker():
            barrier.wait()
            try:
                pay("0xaws", 10.0, token, store=store)
                with results_lock:
                    results.append("ok")
            except RailRejected:
                with results_lock:
                    results.append("rejected")

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start(); t2.start()
        t1.join(); t2.join()

        n_ok = results.count("ok")
        if n_ok > 1:
            double_releases += 1
        if n_ok == 0:
            zero_releases += 1

    check(f"{trials} concurrent trials: ZERO double-releases", double_releases == 0,
          f"{double_releases} double-releases")
    check(f"{trials} concurrent trials: every trial released exactly once",
          zero_releases == 0, f"{zero_releases} zero-release trials")


if __name__ == "__main__":
    test_reverify()
    test_nonce_replay_sequential()
    test_nonce_concurrent_race()
    test_nonce_concurrent_race_stress()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    sys.exit(1 if _FAIL else 0)
