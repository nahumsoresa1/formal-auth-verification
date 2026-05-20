"""
LLM client — talks to Ollama running locally.

Ollama setup (one-time):
  1. Install: https://ollama.com/download
  2. Pull a model: ollama pull llama3.1
  3. Make sure Ollama is running (it starts automatically on Mac after install)

No API key, no cost, runs entirely on your machine.
"""

import re
import requests
import json
from prompts import (
    SYSTEM_PROMPT,
    GENERATE_SPEC_PROMPT,
    ANALYZE_VIOLATION_PROMPT,
    FIX_SPEC_PROMPT,
)

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1"  # change to "llama3.1:70b" if you have 32GB+ RAM


def _extract_tla_block(text: str) -> str:
    """Extract TLA+ code from a markdown ```tla ... ``` block."""
    match = re.search(r"```tla\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    match = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def _call_ollama(prompt: str) -> str:
    """Send a prompt to Ollama and stream the response back."""
    payload = {
        "model": MODEL,
        "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
        "stream": True,
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, stream=True, timeout=120)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Cannot connect to Ollama. Make sure it's running.\n"
            "Install: https://ollama.com/download\n"
            "Then run: ollama pull llama3.1"
        )

    collected = []
    for line in response.iter_lines():
        if line:
            chunk = json.loads(line)
            token = chunk.get("response", "")
            print(token, end="", flush=True)
            collected.append(token)
            if chunk.get("done"):
                break

    print()  # newline after stream
    return "".join(collected)


def generate_spec(protocol_description: str, module_name: str) -> str:
    """Ask the LLM to generate a TLA+ spec. Returns raw TLA+ text."""
    print(f"\n Generating TLA+ spec for: {module_name}\n{'─' * 60}")
    prompt = GENERATE_SPEC_PROMPT.format(
        protocol_description=protocol_description,
        module_name=module_name,
    )
    response = _call_ollama(prompt)
    return _extract_tla_block(response)


def analyze_violation(spec: str, tlc_output: str) -> str:
    """Ask the LLM to explain the attack from a TLC counterexample."""
    print(f"\n Analyzing counterexample...\n{'─' * 60}")
    prompt = ANALYZE_VIOLATION_PROMPT.format(
        spec=spec,
        tlc_output=tlc_output,
    )
    return _call_ollama(prompt)


def fix_spec(spec: str, attack_summary: str, module_name: str) -> str:
    """Ask the LLM to generate a fixed spec. Returns raw TLA+ text."""
    print(f"\n Generating fixed spec...\n{'─' * 60}")
    prompt = FIX_SPEC_PROMPT.format(
        spec=spec,
        attack_summary=attack_summary,
        module_name=module_name,
    )
    response = _call_ollama(prompt)
    return _extract_tla_block(response)


def summarize_attack(analysis: str) -> str:
    """Pull a one-line summary from the attack analysis."""
    for line in analysis.splitlines():
        line = line.strip()
        if any(kw in line.lower() for kw in ["attack", "vulnerability", "exploit", "replay", "intercept", "impersonat"]):
            return line[:300]
    return analysis[:300]
