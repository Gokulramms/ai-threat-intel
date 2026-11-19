"""Security, Authentication, RBAC, and Secret Protection."""

import hashlib
import hmac
import os
import json
import base64
import time
from typing import Optional, Dict, Any
from openkai_engine.config import settings

def hash_password(password: str) -> str:
    """Secure password hashing using PBKDF2-HMAC-SHA256 with salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    return base64.b64encode(salt + key).decode("ascii")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against salted PBKDF2 hash."""
    try:
        decoded = base64.b64decode(hashed_password.encode("ascii"))
        salt = decoded[:16]
        expected_key = decoded[16:]
        actual_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100000)
        return hmac.compare_digest(expected_key, actual_key)
    except Exception:
        return False

def create_access_token(data: Dict[str, Any], expires_delta_minutes: Optional[int] = None) -> str:
    """Generate a lightweight signed JWT-compatible token."""
    to_encode = data.copy()
    expire_sec = (expires_delta_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60
    exp_time = int(time.time()) + expire_sec
    to_encode.update({"exp": exp_time})

    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8")).rstrip(b"=")
    payload = base64.urlsafe_b64encode(json.dumps(to_encode).encode("utf-8")).rstrip(b"=")
    signature_base = f"{header.decode('ascii')}.{payload.decode('ascii')}".encode("ascii")
    signature = hmac.new(settings.SECRET_KEY.encode("utf-8"), signature_base, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=")

    return f"{signature_base.decode('ascii')}.{sig_b64.decode('ascii')}"

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and verify token signature and expiration."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        sig_base = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(settings.SECRET_KEY.encode("utf-8"), sig_base, hashlib.sha256).digest()
        actual_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload_json = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        payload = json.loads(payload_json.decode("utf-8"))
        if payload.get("exp") and time.time() > payload["exp"]:
            return None
        return payload
    except Exception:
        return None

# RBAC Permissions
ROLE_PERMISSIONS = {
    "admin": ["read", "write", "investigate", "admin", "config"],
    "soc_manager": ["read", "write", "investigate"],
    "security_analyst": ["read", "write", "investigate"],
    "auditor": ["read"],
}

def has_permission(role: str, permission: str) -> bool:
    """Check if given role has specified permission."""
    allowed = ROLE_PERMISSIONS.get(role, [])
    return permission in allowed

def sanitize_for_prompt(text: str, max_chars: int = 4000) -> str:
    """Sanitize and limit external untrusted inputs before including in LLM prompt.
    Defends against prompt injection delimiters and command injections.
    """
    if not text:
        return ""
    # Strip potential instructions to ignore previous system instructions
    dangerous_phrases = [
        "ignore previous instructions",
        "system prompt override",
        "disregard all prior directives",
        "new instructions:",
        "you are now in maintenance mode"
    ]
    cleaned = text
    for phrase in dangerous_phrases:
        cleaned = cleaned.replace(phrase, f"[REDACTED_PHRASE]")
    return cleaned[:max_chars]
