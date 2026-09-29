"""Minimal Ollama client (stdlib only). Every call is optional: callers must
handle `None` and fall back to deterministic logic."""
from __future__ import annotations

import json
import os
import urllib.request

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("PRIVACYGUARD_MODEL", "qwen2.5:7b")


def generate(prompt: str, as_json: bool = False, timeout: float = 30.0) -> str | None:
    body = {"model": MODEL, "prompt": prompt, "stream": False,
            "options": {"temperature": 0}}
    if as_json:
        body["format"] = "json"
    req = urllib.request.Request(f"{OLLAMA_URL}/api/generate", json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())["response"]
    except Exception:
        return None


def available() -> bool:
    try:
        urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=2)
        return True
    except Exception:
        return False
