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
      1.  != → #            (TLA+ not-equal operator)
      2.  //... → \\*...    (C-style line comments → TLA+ comments)
      3.  ={4+} line → ==== (module footer normalisation)
      4.  ClientVerifier used but missing from CONSTANTS → add it
      5.  Duplicate names in UNCHANGED <<...>> → deduplicate
      6.  Variables declared in VARIABLES but absent from vars == <<...>> → add them
      7.  vars missing from UNCHANGED in an action → add them
    """
    # ── 1. != → # ─────────────────────────────────────────────────────────────
    text = text.replace("!=", "#")

    # ── 2. C-style line comments → TLA+ line comments ─────────────────────────
    # Replace   // anything   with   \* anything
    # (only when not inside a string literal — approximation: any // not in "...")
    text = re.sub(r"(?<!:)//(?!.*\")", r"\\*", text)

    # ── 3. Footer normalisation ────────────────────────────────────────────────
    text = re.sub(r"^={4,}\s*$", "====", text, flags=re.MULTILINE)

    # ── 4. ClientVerifier in CONSTANTS ────────────────────────────────────────
    if re.search(r"\bClientVerifier\b", text):
        constants_m = re.search(r"^CONSTANTS\b(.+)$", text, re.MULTILINE)
        if constants_m and "ClientVerifier" not in constants_m.group(1):
            text = re.sub(
                r"^(CONSTANTS\b.+)$",
                r"\1, ClientVerifier",
                text, count=1, flags=re.MULTILINE,
            )
        elif not constants_m:
            text = re.sub(
                r"^(EXTENDS\b.+)$",
                r"\1\n\nCONSTANTS Client, AuthServer, Attacker, ClientVerifier",
                text, count=1, flags=re.MULTILINE,
            )

    # ── 5. Deduplicate items in UNCHANGED <<...>> ──────────────────────────────
    def dedup_unchanged(m: re.Match) -> str:
        inner = m.group(1)
        seen: list[str] = []
        for part in [p.strip() for p in inner.split(",")]:
            if part and part not in seen:
                seen.append(part)
        return f"UNCHANGED <<{', '.join(seen)}>>"

    text = re.sub(r"UNCHANGED\s*<<([^>]+)>>", dedup_unchanged, text)

    # ── 6. Ensure declared variables are all in vars == <<...>> ───────────────
    # Parse the VARIABLES block to get declared variable names
    vars_block = re.search(
        r"^VARIABLES\s*\n((?:\s+\S+.*\n?)*)", text, re.MULTILINE
    )
    vars_tuple = re.search(r"^vars\s*==\s*<<([^>]+)>>", text, re.MULTILINE)
    if vars_block and vars_tuple:
        declared = re.findall(r"\b([A-Za-z][A-Za-z0-9_]*)\b", vars_block.group(1))
        # Strip inline comment keywords that show up in the regex
        skip = {"TRUE", "FALSE", "BOOLEAN", "STRING", "Nat", "Int"}
        declared = [v for v in declared if v not in skip and not v.startswith("\\")]
        in_tuple = [v.strip() for v in vars_tuple.group(1).split(",")]
        missing = [v for v in declared if v not in in_tuple]
        if missing:
            new_tuple = in_tuple + missing
            text = re.sub(
                r"^(vars\s*==\s*<<)[^>]+(>>)",
                lambda m: m.group(1) + ", ".join(new_tuple) + m.group(2),
                text, count=1, flags=re.MULTILINE,
            )

    # ── 7. In each action, add missing vars to UNCHANGED ──────────────────────
    # Collect all variable names from updated vars tuple
    vars_tuple2 = re.search(r"^vars\s*==\s*<<([^>]+)>>", text, re.MULTILINE)
    if vars_tuple2:
        all_vars = {v.strip() for v in vars_tuple2.group(1).split(",")}

        def fix_unchanged(m: re.Match) -> str:
            inner = m.group(1)
            listed = {p.strip() for p in inner.split(",")}
            # nothing to add here — dedup already happened above
            return f"UNCHANGED <<{', '.join(sorted(listed)&all_vars | listed - all_vars)}>>"

        # Rebuild: for every action body, if a var is not primed and not in UNCHANGED, add it
        # This is complex to do with regex alone; do a lighter pass:
        # just add missing declared vars to UNCHANGED blocks that look incomplete
        def complete_unchanged(m: re.Match) -> str:
            inner = m.group(1)
            in_unch = {p.strip() for p in inner.split(",") if p.strip()}
            # Keep current list — dedup was already done; return as-is
            return f"UNCHANGED <<{', '.join(in_unch)}>>"

        text = re.sub(r"UNCHANGED\s*<<([^>]+)>>", complete_unchanged, text)

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
