"""
LLM client — talks to Ollama running locally.

Ollama setup (one-time):
  1. Install: brew install ollama
  2. Start server: ollama serve
  3. Pull model: ollama pull llama3.1
"""

import re
import ollama
from prompts import (
    SYSTEM_PROMPT,
    ANALYZE_VIOLATION_PROMPT,
    FIX_SPEC_PROMPT,
    FIX_SPEC_RETRY_PROMPT,
)

MODEL = "llama3.1"


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
    """Send a prompt to Ollama and stream the response."""
    collected = []
    stream = ollama.chat(
        model=MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        stream=True,
    )
    for chunk in stream:
        token = chunk["message"]["content"]
        print(token, end="", flush=True)
        collected.append(token)
    print()
    return "".join(collected)


def analyze_violation(spec: str, tlc_output: str) -> str:
    """Ask the LLM to explain the attack from a TLC counterexample."""
    print(f"\n Analyzing counterexample...\n{'─' * 60}")
    prompt = ANALYZE_VIOLATION_PROMPT.format(
        spec=spec,
        tlc_output=tlc_output,
    )
    return _call_ollama(prompt)


def generate_fix(
    spec: str,
    attack_summary: str,
    fixed_module_name: str,
    previous_error: str = None,
) -> str:
    """
    Ask the LLM to generate a corrected TLA+ spec that blocks the discovered attack.
    Returns raw TLA+ text (no markdown fences).

    On the first attempt (previous_error=None) uses FIX_SPEC_PROMPT.
    On retries (previous_error set) uses FIX_SPEC_RETRY_PROMPT, which includes
    the specific parse error or violation so the LLM can learn from its mistake.

    This is the core of the generative loop:
      LLM explains attack → LLM proposes fix → TLC verifies fix → repeat if needed
    """
    if previous_error:
        print(f"\n🔧 Retrying fixed spec (with error feedback): {fixed_module_name}\n{'─' * 60}")
        prompt = FIX_SPEC_RETRY_PROMPT.format(
            spec=spec,
            attack_summary=attack_summary,
            fixed_module_name=fixed_module_name,
            previous_error=previous_error[:800],   # keep prompt size reasonable
        )
    else:
        print(f"\n🔧 Generating fixed spec: {fixed_module_name}\n{'─' * 60}")
        prompt = FIX_SPEC_PROMPT.format(
            spec=spec,
            attack_summary=attack_summary,
            fixed_module_name=fixed_module_name,
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
