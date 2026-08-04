import os, json, hmac, hashlib, base64, time, secrets

# Signing secret comes from env ONLY. Never hardcoded, no unsigned fallback.
_SECRET_ENV = "CLAWCLEAR_SIGNING_SECRET"

# Clearance tokens are short-lived by design.
TOKEN_TTL_SECONDS = 60


class SigningSecretMissing(RuntimeError):
    """Raised when the signing secret env var is absent -> fail closed."""


class TokenInvalid(Exception):
    """Token failed signature, binding, or expiry verification."""


def _get_secret() -> bytes:
    secret = os.environ.get(_SECRET_ENV)
    if not secret:
        # Fail CLOSED: refuse to issue/verify rather than fall back to unsigned.
        raise SigningSecretMissing(
            f"{_SECRET_ENV} not set; refusing to issue/verify clearance tokens"
        )
    return secret.encode("utf-8")


def _canonical(destination: str, amount: float, nonce: str, exp: int) -> bytes:
    # Deterministic serialization so signer and verifier agree byte-for-byte.
    payload = {
        "destination": destination,
        "amount": round(float(amount), 8),
        "nonce": nonce,
        "exp": int(exp),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def issue_token(destination: str, amount: float, ttl: int = TOKEN_TTL_SECONDS) -> dict:
    """Issue a clearance token BOUND to this exact destination+amount.

    Returns {token, nonce, exp}. Raises SigningSecretMissing if no secret.
    """
    secret = _get_secret()
    nonce = secrets.token_urlsafe(16)
    exp = int(time.time()) + int(ttl)
    body = _canonical(destination, amount, nonce, exp)
    sig = hmac.new(secret, body, hashlib.sha256).digest()
    token = f"{_b64e(body)}.{_b64e(sig)}"
    return {"token": token, "nonce": nonce, "exp": exp}


def verify_token(token: str, destination: str, amount: float) -> dict:
    """Verify signature, binding (destination+amount), and expiry.

    Returns the decoded payload on success. Raises TokenInvalid otherwise,
    SigningSecretMissing if no secret is configured (fail closed).
    """
    secret = _get_secret()
    try:
        body_b64, sig_b64 = token.split(".", 1)
        body = _b64d(body_b64)
        sig = _b64d(sig_b64)
    except Exception:
        raise TokenInvalid("malformed token")

    expected = hmac.new(secret, body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise TokenInvalid("bad signature")

    try:
        payload = json.loads(body)
    except Exception:
        raise TokenInvalid("undecodable payload")

    # Binding check: token cleared for one payment can't be replayed for another.
    if payload.get("destination") != destination:
        raise TokenInvalid("destination mismatch")
    if round(float(payload.get("amount", -1)), 8) != round(float(amount), 8):
        raise TokenInvalid("amount mismatch")

    # Expiry check.
    if int(time.time()) >= int(payload.get("exp", 0)):
        raise TokenInvalid("token expired")

    return payload
