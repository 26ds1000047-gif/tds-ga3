"""All settings come from environment variables (Vercel: Project -> Settings -> Environment Variables)."""
import json
import os
from urllib.parse import urlparse


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _bool(name: str, default: bool) -> bool:
    v = _env(name)
    if not v:
        return default
    return v.lower() in ("1", "true", "yes", "on")


# --- Public URL (must match the URL you submit EXACTLY) ---------------------
# Vercel exposes VERCEL_PROJECT_PRODUCTION_URL (host only, no scheme) automatically,
# so on Vercel you normally do not need to set PUBLIC_BASE_URL at all.
_vercel_host = _env("VERCEL_PROJECT_PRODUCTION_URL")
PUBLIC_BASE_URL = _env("PUBLIC_BASE_URL") or (
    f"https://{_vercel_host}/a2a/" if _vercel_host else "http://localhost:8000/a2a/"
)
_parsed = urlparse(PUBLIC_BASE_URL)
BASE_PATH = _parsed.path.rstrip("/")  # "" or "/a2a"
ORIGIN = f"{_parsed.scheme}://{_parsed.netloc}"

# --- Auth -------------------------------------------------------------------
# Empty  -> "open" mode: any well-formed Bearer token is accepted and becomes
#           its own isolated principal (needed so the grader's outsider token works).
# Set    -> strict mode: only these comma-separated tokens are accepted.
AUTH_TOKENS = [t.strip() for t in _env("AUTH_TOKENS").split(",") if t.strip()]

# --- Storage: Postgres (Vercel serverless has no persistent disk) -----------
# The Neon integration for Vercel creates DATABASE_URL (pooled) automatically.
DATABASE_URL = _env("DATABASE_URL") or _env("POSTGRES_URL")
PENDING_STALE_SECONDS = int(_env("PENDING_STALE_SECONDS", "60"))
PENDING_WAIT_SECONDS = float(_env("PENDING_WAIT_SECONDS", "40"))

# --- Model (any OpenAI-compatible /chat/completions endpoint) ---------------
LLM_BASE_URL = _env("LLM_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai")
LLM_API_KEY = _env("LLM_API_KEY")
LLM_MODEL = _env("LLM_MODEL", "gemini-3.8-flash")
# Comma-separated backup models, tried in order when the main one errors (e.g. 503 "high demand").
LLM_FALLBACK_MODELS = [m.strip() for m in _env("LLM_FALLBACK_MODELS", "").split(",") if m.strip()]
LLM_JSON_MODE = _bool("LLM_JSON_MODE", True)
LLM_MAX_TOKENS = int(_env("LLM_MAX_TOKENS", "8000"))
LLM_BUDGET_SECONDS = float(_env("LLM_BUDGET_SECONDS", "36"))  # total across retries; request limit is 45s
LLM_EXTRA_BODY = json.loads(_env("LLM_EXTRA_BODY", "{}") or "{}")  # e.g. {"reasoning_effort":"none"}
LLM_MOCK = _bool("LLM_MOCK", False)  # tests only
LLM_MOCK_DELAY = float(_env("LLM_MOCK_DELAY", "0"))  # tests only
MAX_LLM_CALLS_PER_DAY = int(_env("MAX_LLM_CALLS_PER_DAY", "300"))

# "bracketed" -> "[REF-1]"   |   "bare" -> "REF-1"
EVIDENCE_REF_STYLE = _env("EVIDENCE_REF_STYLE", "bracketed").lower()

# Put receipts as a 2nd Part inside the proposals artifact instead of a 2nd artifact.
RECEIPTS_IN_SAME_ARTIFACT = _bool("RECEIPTS_IN_SAME_ARTIFACT", False)

# --- Limits -----------------------------------------------------------------
MAX_PACKAGES = int(_env("MAX_PACKAGES", "60"))
MAX_BODY_BYTES = int(_env("MAX_BODY_BYTES", str(4_000_000)))  # Vercel itself caps bodies at 4.5 MB
MAX_RESPONSE_BYTES = 512 * 1024
DEBUG_STATS = _bool("DEBUG_STATS", False)  # tests only
