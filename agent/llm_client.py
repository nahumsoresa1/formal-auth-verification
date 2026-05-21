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


def _sanitize_tla(text: str) -> str:
    """
    Auto-correct the most common TLA+ syntax errors that LLMs produce.
    Applied to every generated spec before it is written to disk.

    Fixes applied:
      1. != → #  (TLA+ not-equal operator)
      2. Any line of 4+ '=' signs → ====  (module footer)
      3. ClientVerifier used but missing from CONSTANTS → add it
      4. Duplicate var names in UNCHANGED (e.g. <<phase, ..., phase>>) → deduplicate
    """
    # ── 1. != → # ─────────────────────────────────────────────────────────────
    text = text.replace("!=", "#")

    # ── 2. Footer normalisation ────────────────────────────────────────────────
    # A line that is only '=' chars (4 or more, with optional trailing whitespace)
    text = re.sub(r"^={4,}\s*$", "====", text, flags=re.MULTILINE)

    # ── 3. ClientVerifier in CONSTANTS ────────────────────────────────────────
    if re.search(r"\bClientVerifier\b", text):
        constants_m = re.search(r"^CONSTANTS\b(.+)$", text, re.MULTILINE)
        if constants_m and "ClientVerifier" not in constants_m.group(1):
            # Append to existing CONSTANTS line
            text = re.sub(
                r"^(CONSTANTS\b.+)$",
                r"\1, ClientVerifier",
                text, count=1, flags=re.MULTILINE,
            )
        elif not constants_m:
            # No CONSTANTS block at all — inject one after EXTENDS
            text = re.sub(
                r"^(EXTENDS\b.+)$",
                r"\1\n\nCONSTANTS Client, AuthServer, Attacker, ClientVerifier",
                text, count=1, flags=re.MULTILINE,
            )

    # ── 4. Deduplicate items in UNCHANGED <<...>> ──────────────────────────────
    def dedup_unchanged(m: re.Match) -> str:
        inner = m.group(1)
        seen: list[str] = []
        for part in [p.strip() for p in inner.split(",")]:
            if part and part not in seen:
                seen.append(part)
        return f"UNCHANGED <<{', '.join(seen)}>>"

    text = re.sub(r"UNCHANGED\s*<<([^>]+)>>", dedup_unchanged, text)

    return text


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
    raw = _extract_tla_block(response)
    return _sanitize_tla(raw)


def summarize_attack(analysis: str) -> str:
    """Pull a one-line summary from the attack analysis."""
    for line in analysis.splitlines():
        line = line.strip()
        if any(kw in line.lower() for kw in ["attack", "vulnerability", "exploit", "replay", "intercept", "impersonat"]):
            return line[:300]
    return analysis[:300]
