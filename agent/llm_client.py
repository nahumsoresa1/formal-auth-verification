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


def _parse_declared_vars(text: str) -> list[str]:
    """
    Extract variable names from a TLA+ VARIABLES block.
    Strips inline comments (\\* ...) before searching so comment words
    like 'idle', 'code', 'issued' don't appear as false positives.
    Only matches identifiers that appear ALONE on a line (before an
    optional comma), which is the standard TLA+ variable-list format.
    """
    m = re.search(r"^VARIABLES\s*\n((?:[ \t]+[^\n]*\n)*)", text, re.MULTILINE)
    if not m:
        return []
    raw = m.group(1)
    # Strip TLA+ inline comments: \* or (* ... *) style on same line
    stripped = re.sub(r"\\?\*[^\n]*", "", raw)
    stripped = re.sub(r"\(\*[^*]*\*\)", "", stripped)
    # Match lines that contain only an identifier (+ optional trailing comma)
    names = re.findall(r"^\s*([A-Za-z][A-Za-z0-9_]*)\s*,?\s*$", stripped, re.MULTILINE)
    return [n for n in names if n]


def _complete_unchanged_blocks(text: str, all_vars: set[str]) -> str:
    """
    For every UNCHANGED <<...>> clause in the spec, find any declared
    variable that is neither primed in the same action NOR listed in the
    clause, and add it.  Uses a line-by-line scan so it never needs a
    nested closure over a mutating string.
    """
    result: list[str] = []
    last = 0

    for m in re.finditer(r"UNCHANGED\s*<<([^>]+)>>", text):
        pos = m.start()
        # Locate the start of the enclosing action (blank line before it)
        action_start = text.rfind("\n\n", 0, pos)
        action_start = action_start + 2 if action_start >= 0 else 0
        context = text[action_start:pos]

        # Primed variables: var' = ... or var' \in ...
        primed = set(re.findall(r"\b([A-Za-z][A-Za-z0-9_]*)'\s*(?:=|\\in|\\notin)", context))

        # Remove any variable that is already primed in this action
        in_unch = [p.strip() for p in m.group(1).split(",")
                   if p.strip() and p.strip() not in primed]
        missing = sorted(all_vars - primed - set(in_unch))

        result.append(text[last:pos])
        if missing:
            result.append(f"UNCHANGED <<{', '.join(in_unch + missing)}>>")
        else:
            result.append(m.group(0))
        last = m.end()

    result.append(text[last:])
    return "".join(result)


def _fix_variables_commas(text: str) -> str:
    """
    Ensure every variable in a VARIABLES block has a trailing comma except
    the last one.  LLMs frequently forget the comma when they append a new
    variable at the end, causing TLC to fail with 'Unexpected symbol'.
    """
    m = re.search(r"(^VARIABLES\b[^\n]*\n)((?:[ \t]+[^\n]*\n)*)", text, re.MULTILINE)
    if not m:
        return text

    header = m.group(1)
    block  = m.group(2)
    lines  = block.splitlines(keepends=True)

    # Identify lines that are variable declarations (identifier ± trailing comma)
    var_indices = []
    for i, line in enumerate(lines):
        clean = re.sub(r"\\\*[^\n]*", "", line)    # strip \* … comments
        clean = re.sub(r"\(\*.*?\*\)", "", clean)  # strip (* … *) comments
        if re.match(r"^\s+[A-Za-z][A-Za-z0-9_]*\s*,?\s*$", clean):
            var_indices.append(i)

    if len(var_indices) < 2:
        return text

    new_lines = list(lines)
    for pos, li in enumerate(var_indices):
        line    = new_lines[li]
        is_last = (pos == len(var_indices) - 1)

        cm = re.search(r"\\\*", line)
        if cm:
            before  = line[:cm.start()].rstrip()
            comment = "   " + line[cm.start():]  # keep comment with spacing
        else:
            before  = line.rstrip("\n").rstrip()
            comment = "\n"

        if before.endswith(","):
            before = before[:-1]
        if not is_last:
            before += ","

        new_lines[li] = before + comment

    return text[: m.start()] + header + "".join(new_lines) + text[m.end() :]


def _comment_bare_prose(text: str) -> str:
    """
    Prefix unindented English-prose lines with \\* so TLC does not try to
    parse them as TLA+.

    LLMs sometimes emit lines like:
        The access token must only ever be held by the legitimate client.
    outside of comment blocks.  We detect these conservatively: an unindented
    line that starts with Capital+lowercase, contains ≥3 words, and contains
    no TLA+ operator tokens.
    """
    _TLA_OPS = re.compile(
        r"==|/\\|\\/|<<|>>|:=|\|->|\\in\b|\\notin\b|#"
        r"|\bUNCHANGED\b|\bEXTENDS\b|\bCONSTANTS\b|\bVARIABLES\b"
    )

    result = []
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        indent   = line[: len(line) - len(stripped)]

        # Leave indented lines, empty lines, and already-commented lines alone
        if (indent
                or not stripped
                or stripped.startswith("\\*")
                or stripped.startswith("(*")
                or stripped.startswith("-")
                or stripped.startswith("=")):
            result.append(line)
            continue

        if (re.match(r"[A-Z][a-z]", stripped)
                and stripped.count(" ") >= 2
                and not _TLA_OPS.search(stripped)):
            result.append("\\* " + stripped)
        else:
            result.append(line)

    return "".join(result)


def _sanitize_tla(text: str) -> str:
    """
    Auto-correct the most common TLA+ syntax errors that LLMs produce.
    Applied to every generated spec before it is written to disk.

    Fixes applied:
      1.  != → #               (TLA+ not-equal operator)
      2.  //... → \\*...       (C-style line comments → TLA+ line comments)
      3.  Bare prose lines → \\* prose  (unindented English sentences → comments)
      4.  \\/* → \\*           (disjunction fused with comment marker)
      5.  ={4+} line → ====    (module footer normalisation)
      6.  [guard] ActionName in Next → ActionName  (invalid bracket guards)
      7.  ClientVerifier missing from CONSTANTS → add it
      8.  Duplicate names in UNCHANGED <<...>> → deduplicate
      9.  Missing/extra commas in VARIABLES block → normalise
      10. vars tuple rebuilt to match exactly the declared VARIABLES
      11. Variables missing from an UNCHANGED clause → add them
          Primed variables removed from UNCHANGED if they conflict
    """
    # ── 1. != → # ─────────────────────────────────────────────────────────────
    text = text.replace("!=", "#")

    # ── 2. // line comments → \* ──────────────────────────────────────────────
    text = re.sub(r"(?<!:)//", r"\\*", text)

    # ── 3. Bare prose lines → comments ────────────────────────────────────────
    text = _comment_bare_prose(text)

    # ── 4. \/* (disjunction fused with comment) → \* ──────────────────────────
    text = re.sub(r"\\/\*", r"\\*", text)

    # ── 5. Footer normalisation ───────────────────────────────────────────────
    text = re.sub(r"^={4,}\s*$", "====", text, flags=re.MULTILINE)

    # ── 6. Fix/rebuild malformed Next == block  ───────────────────────────────
    # Pass A: strip `[guard] ActionName` → `ActionName` (invalid bracket guards)
    # Pass B: strip `[ActionName]` → `ActionName` inside expressions
    # Pass C: if Next still contains comments or conjunctions, rebuild it from
    #         the PascalCase action names visible in the broken body.
    next_m = re.search(r"^(Next\s*==)\s*\n((?:[ \t]+[^\n]*\n)*)", text, re.MULTILINE)
    if next_m:
        body = next_m.group(2)
        # Pass A
        body = re.sub(r"\[\s*[^\]]*\]\s*([A-Za-z][A-Za-z0-9_]*)", r"\1", body)
        # Pass B: [ActionName] → ActionName (not followed by _ to avoid [Next]_vars)
        body = re.sub(r"\[([A-Za-z][A-Za-z0-9_]*)\](?!_)", r"\1", body)

        _MALFORMED = re.compile(r"^\s*\\/\s*\(|^\s*\\/\s*\\+\*|^\s*\\+\*", re.MULTILINE)
        if _MALFORMED.search(body):
            # Pass C: rebuild — only keep identifiers actually defined in the spec
            defined_ops = set(re.findall(r"^([A-Za-z][A-Za-z0-9_]*)\s*==", text, re.MULTILINE))
            non_actions = {"Init", "Spec", "Next", "vars"} | set(_parse_declared_vars(text))
            non_actions.update(
                op for op in defined_ops
                if re.search(rf"^{re.escape(op)}\s*==\s*\n?\s*[^\\/]", text, re.MULTILINE)
                   and not re.search(r"/\\", text[text.find(op):text.find(op) + 200])
            )
            candidates = re.findall(r"\b([A-Za-z][A-Za-z0-9_]*)\b", body)
            actions = list(dict.fromkeys(
                c for c in candidates
                if c in defined_ops and c not in non_actions
            ))
            if actions:
                body = "".join(f"  \\/ {a}\n" for a in actions)

        text = text[: next_m.start()] + next_m.group(1) + "\n" + body + text[next_m.end() :]

    # ── 7. ClientVerifier in CONSTANTS ────────────────────────────────────────
    if re.search(r"\bClientVerifier\b", text):
        cm = re.search(r"^CONSTANTS\b(.+)$", text, re.MULTILINE)
        if cm and "ClientVerifier" not in cm.group(1):
            text = re.sub(r"^(CONSTANTS\b.+)$", r"\1, ClientVerifier",
                          text, count=1, flags=re.MULTILINE)
        elif not cm:
            text = re.sub(r"^(EXTENDS\b.+)$",
                          r"\1\n\nCONSTANTS Client, AuthServer, Attacker, ClientVerifier",
                          text, count=1, flags=re.MULTILINE)

    # ── 8. Deduplicate UNCHANGED ──────────────────────────────────────────────
    def _dedup(m: re.Match) -> str:
        seen: list[str] = []
        for p in [x.strip() for x in m.group(1).split(",")]:
            if p and p not in seen:
                seen.append(p)
        return f"UNCHANGED <<{', '.join(seen)}>>"
    text = re.sub(r"UNCHANGED\s*<<([^>]+)>>", _dedup, text)

    # ── 9. Fix VARIABLES commas ───────────────────────────────────────────────
    text = _fix_variables_commas(text)

    # ── 10 & 11. Variable completeness ────────────────────────────────────────
    declared = _parse_declared_vars(text)

    if declared:
        # 10. Rebuild vars == <<...>> tuple to contain exactly the declared variables.
        vt = re.search(r"^vars\s*==\s*<<([^>]+)>>", text, re.MULTILINE)
        if vt:
            in_tuple = [v.strip() for v in vt.group(1).split(",") if v.strip()]
            declared_set = set(declared)
            has_garbage = any(v not in declared_set for v in in_tuple)
            missing = [v for v in declared if v not in in_tuple]
            if has_garbage or missing:
                text = re.sub(
                    r"^(vars\s*==\s*<<)[^>]+(>>)",
                    lambda mm: mm.group(1) + ", ".join(declared) + mm.group(2),
                    text, count=1, flags=re.MULTILINE,
                )

        # 11. Complete UNCHANGED blocks; remove primed vars that conflict
        all_vars = set(declared)
        text = _complete_unchanged_blocks(text, all_vars)

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
