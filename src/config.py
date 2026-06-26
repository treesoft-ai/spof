"""Configuration constants for Spof."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Try loading from env/.env first, then let standard dotenv logic/os.environ handle the rest
env_file = Path("env/.env")
if env_file.exists():
    load_dotenv(dotenv_path=env_file)
else:
    load_dotenv()

__version__ = "0.2.0"

# API keys
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
HACKCLUB_API_KEY = os.environ.get("HACKCLUB_API_KEY", "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")

# Default URLs
HACKCLUB_URL = "https://ai.hackclub.com/proxy/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
AGENTROUTER_URL = "https://agentrouter.org/v1/chat/completions"

# DEFAULT PROVIDER MODELS (Only fallback defaults, can be overridden via --model CLI)
DEFAULT_ANTHROPIC_MODEL = "claude-3-5-sonnet-20241022"
DEFAULT_OPENROUTER_MODEL = "cohere/north-mini-code:free"
DEFAULT_AGENTROUTER_MODEL = "glm-5.2"

MAX_TOOL_ITERATIONS = 15

# Determine default provider based on key availability
if ANTHROPIC_API_KEY:
    DEFAULT_PROVIDER = "anthropic"
elif OPENROUTER_API_KEY:
    DEFAULT_PROVIDER = "openrouter"
else:
    DEFAULT_PROVIDER = "anthropic"  # fallback default

TOOL_DISPLAY_NAMES = {
    "Fetch": "Fetch page",
    "Records": "DNS lookup",
    "CloudCheck": "Cloud API check",
    "LicenseCheck": "License verification",
    "ToolCheck": "Tool installation check",
    "RoleCheck": "Role verification",
    "EnvCheck": "Environment check",
}

# --- AGENTROUTER (EASY TO REMOVE SECTION) ---
AGENTROUTER_KEY = "sk-eTRzi5Wa8x2WMT3zgtrqyAt1QGCElkD7U5gBg2eDfq3lFewz"
# ---------------------------------------------
