#!/usr/bin/env python3
"""
TLA+ Security Verification Agent
==================================
Automatically verifies security protocols using TLA+ and TLC.

The agent:
  1. Loads a pre-written TLA+ spec from specs/
  2. Runs TLC to exhaustively check all reachable states
  3. If a violation is found, uses a local LLM (Ollama) to explain the attack
  4. A pre-written fixed spec is run and the fix is confirmed, OR
     with --generate the LLM generates a fix live, TLC re-verifies it, and the
     loop repeats until the invariant holds (or max iterations reached).

Usage:
  python3 main.py --demo insecure              # replay attack on login protocol
  python3 main.py --demo ns                    # Needham-Schroeder MITM attack
  python3 main.py --demo oauth                 # OAuth 2.0 code interception + PKCE fix
  python3 main.py --demo oauth --generate      # LLM generates the PKCE fix live
  python3 main.py --spec MyProtocol            # run any spec in specs/
  python3 main.py --spec MyProtocol --generate # LLM generates a fix for any broken spec
"""

import sys
import argparse
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import llm_client
import tlc_runner

# ── Built-in demos ─────────────────────────────────────────────────────────────

DEMOS = {
    "insecure": {
        "module":       "InsecureLogin",
        "fixed_module": "SecureLogin",
        "title":        "Insecure Login Protocol",
        "description":  "Plaintext credential transmission — replay attack",
    },
    "ns": {
        "module":       "NeedhamSchroeder",
        "fixed_module": "NeedhamSchroederFixed",
        "title":        "Needham-Schroeder Public Key Protocol (1978)",
        "description":  "Believed secure for 17 years — Lowe found the MITM attack in 1995",
    },
    "oauth": {
        "module":       "OAuth2",
        "fixed_module": "OAuth2Fixed",
        "title":        "OAuth 2.0 Authorization Code Flow",
        "description":  "Authorization code interception — fixed with PKCE (RFC 7636)",
    },
}

# ── Output helpers ─────────────────────────────────────────────────────────────

def banner(text):
    width = 65
    print(f"\n{'═' * width}")
    print(f"  {text}")
    print(f"{'═' * width}\n")

def section(text):
    print(f"\n{'─' * 65}")
    print(f"  {text}")
    print(f"{'─' * 65}")

def ok(text):
    print(f"\n  ✅  {text}")

def fail(text):
    print(f"\n  ❌  {text}")

def info(text):
    print(f"      {text}")

def result_summary(label, passed, states):
    status = "VERIFIED SECURE" if passed else "VIOLATION FOUND"
    symbol = "✅" if passed else "❌"
    states_str = f"  ({states:,} states explored)" if states else ""
    print(f"\n  {symbol}  {label}: {status}{states_str}")

# ── Generative loop helpers ────────────────────────────────────────────────────

def _invariant_from_cfg(module_name: str) -> str:
    """Read the INVARIANT name from a module's .cfg file."""
    specs_dir = Path(__file__).parent.parent / "specs"
    cfg_path  = specs_dir / f"{module_name}.cfg"
    if cfg_path.exists():
        for line in cfg_path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("INVARIANT"):
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[1]
    return None


_CFG_NEXT_SECTION_KEYWORDS = {
    "SPECIFICATION", "INVARIANT", "PROPERTY", "CHECK_DEADLOCK",
    "SYMMETRY", "INIT", "NEXT", "VIEW", "CONSTANT",
}

def _build_cfg_for_generated(module_name: str, invariant: str) -> str:
    """
    Build a .cfg for an LLM-generated spec.

    Copies the FULL CONSTANTS block from the base spec's cfg (not just the
    header line) so TLC has all constant assignments, then appends
    ClientVerifier = verifier1 if it isn't already present.
    """
    specs_dir = Path(__file__).parent.parent / "specs"
    base_name = module_name.replace("LLMFixed", "")
    base_cfg  = specs_dir / f"{base_name}.cfg"

    lines = ["SPECIFICATION Spec"]

    if base_cfg.exists():
        cfg_lines = base_cfg.read_text().splitlines()
        in_constants = False
        constants_block: list[str] = []
        has_client_verifier = False

        for line in cfg_lines:
            stripped = line.strip()
            if stripped.upper().startswith("CONSTANTS"):
                in_constants = True
                constants_block.append(line)
                if "ClientVerifier" in line:
                    has_client_verifier = True
            elif in_constants:
                first_word = stripped.split()[0] if stripped.split() else ""
                if first_word.upper() in _CFG_NEXT_SECTION_KEYWORDS:
                    in_constants = False          # done reading CONSTANTS
                else:
                    constants_block.append(line)
                    if "ClientVerifier" in line:
                        has_client_verifier = True

        if constants_block:
            lines.extend(constants_block)
            if not has_client_verifier:
                lines.append("  ClientVerifier = verifier1")
        else:
            # Base cfg has no CONSTANTS block — build a minimal one
            lines.append("CONSTANTS")
            lines.append("  ClientVerifier = verifier1")

    if invariant:
        lines.append(f"INVARIANT {invariant}")
    lines.append("CHECK_DEADLOCK FALSE")
    return "\n".join(lines) + "\n"


def generative_loop(
    module_name: str,
    base_result: tlc_runner.TLCResult,
    max_iterations: int = 3,
) -> bool:
    """
    Core of Level 2:
      1. LLM explains the attack and produces a one-line summary
      2. LLM generates a fixed TLA+ spec
      3. TLC verifies the generated spec
      4. If the invariant still fails, loop up to max_iterations

    Returns True if a working fix was found, False otherwise.
    """
    specs_dir        = Path(__file__).parent.parent / "specs"
    spec_text        = (specs_dir / f"{module_name}.tla").read_text()
    fixed_module_name = f"{module_name}LLMFixed"

    # ── Step 1: LLM explains the attack ───────────────────────────────────────
    section("LLM Attack Analysis")
    analysis       = llm_client.analyze_violation(spec_text, base_result.output)
    attack_summary = llm_client.summarize_attack(analysis)

    invariant = _invariant_from_cfg(module_name)
    previous_error: str = None   # fed back to the LLM on retries

    for iteration in range(1, max_iterations + 1):
        section(f"Generative Loop — Iteration {iteration} of {max_iterations}")

        # ── Step 2: LLM generates (or retries) the fix ────────────────────────
        generated_tla = llm_client.generate_fix(
            spec_text,
            attack_summary,
            fixed_module_name,
            previous_error=previous_error,
        )

        if not generated_tla or len(generated_tla) < 50:
            previous_error = "The response contained no valid TLA+ code block."
            fail("LLM did not produce a valid TLA+ block — retrying.")
            continue

        # ── Step 3: Write spec + cfg to disk ──────────────────────────────────
        fixed_tla_path = specs_dir / f"{fixed_module_name}.tla"
        fixed_cfg_path = specs_dir / f"{fixed_module_name}.cfg"
        fixed_tla_path.write_text(generated_tla)
        fixed_cfg_path.write_text(_build_cfg_for_generated(fixed_module_name, invariant))
        info(f"Wrote specs/{fixed_module_name}.tla  ({len(generated_tla)} chars)")

        # ── Step 4: TLC verifies ───────────────────────────────────────────────
        section(f"TLC Verification: {fixed_module_name}.tla")
        fixed_result = tlc_runner.run_tlc(fixed_module_name)

        if fixed_result.states_explored:
            info(f"States explored: {fixed_result.states_explored:,}")

        is_parse_error = (
            "Parse Error" in fixed_result.output
            or "Parsing or semantic analysis failed" in fixed_result.output
            or "***Parse" in fixed_result.output
        )

        if is_parse_error:
            # Extract the lines that describe the actual TLC error, not boilerplate
            SKIP_PREFIXES = ("TLC2", "Warning", "Running ", "(Mac", "(Use", "Parsing file")
            SKIP_SUBSTRINGS = ("jar:file",)
            USEFUL_KEYWORDS = ("***", "Error", "error", "Unexpected", "undefined",
                               "undeclared", "line ", " col ", "Parse")

            all_lines = fixed_result.output.splitlines()
            # First pass: lines that look like actual errors
            error_lines = [
                ln for ln in all_lines
                if any(kw in ln for kw in USEFUL_KEYWORDS)
                and not any(ln.startswith(p) for p in SKIP_PREFIXES)
                and not any(s in ln for s in SKIP_SUBSTRINGS)
            ]
            # Fall back: any non-boilerplate line
            if not error_lines:
                error_lines = [
                    ln for ln in all_lines
                    if ln.strip()
                    and not any(ln.startswith(p) for p in SKIP_PREFIXES)
                    and not any(s in ln for s in SKIP_SUBSTRINGS)
                ]

            previous_error = "\n".join(error_lines[:20])
            fail(f"Iteration {iteration}: parse error in generated spec:")
            print(f"  {previous_error[:400]}")
            continue

        result_summary(fixed_module_name, fixed_result.passed, fixed_result.states_explored)

        if fixed_result.passed:
            ok(f"✨ Fix verified on iteration {iteration}! Attack is no longer possible.")
            _print_comparison(module_name, base_result, fixed_module_name, fixed_result)
            return True

        # Logical violation — extract counterexample as feedback
        fail(f"Iteration {iteration}: invariant still violated — retrying with counterexample.")
        ce = fixed_result.counterexample or ""
        if ce:
            print(f"\n  TLC trace:\n{ce[:600]}")
        previous_error = (
            f"TLC found a violation. The attacker still gets the token.\n"
            f"Counterexample:\n{ce[:500]}\n\n"
            f"The fix must make AttackerExchangeCode IMPOSSIBLE to execute. "
            f"Add the guard /\\ attackerKnowsVerifier = TRUE inside AttackerExchangeCode, "
            f"and never set attackerKnowsVerifier to TRUE anywhere else."
        )

    fail(f"Could not generate a working fix after {max_iterations} iterations.")
    return False


# ── Core verification ──────────────────────────────────────────────────────────

def run_spec(module_name: str) -> tlc_runner.TLCResult:
    """Run TLC on a spec and return the result."""
    specs_dir = Path(__file__).parent.parent / "specs"
    spec_file  = specs_dir / f"{module_name}.tla"

    if not spec_file.exists():
        print(f"\n  Spec not found: specs/{module_name}.tla")
        return None

    section(f"Running TLC on: {module_name}.tla")
    result = tlc_runner.run_tlc(module_name)

    if result.states_explored:
        info(f"States explored: {result.states_explored:,}")

    if "Parse Error" in result.output or "Parsing or semantic analysis failed" in result.output:
        fail("TLC could not parse the spec — syntax error.")
        print(result.output[:800])
        return result

    return result


def explain_attack(module_name: str, result: tlc_runner.TLCResult):
    """Print the counterexample trace and ask the LLM to explain the attack."""
    specs_dir = Path(__file__).parent.parent / "specs"
    spec_text  = (specs_dir / f"{module_name}.tla").read_text()

    section("Counterexample — Attack Trace")
    if result.counterexample:
        lines = result.counterexample.splitlines()
        for line in lines:
            if line.strip():
                print(f"  {line}")

    section("LLM Attack Analysis")
    llm_client.analyze_violation(spec_text, result.output)


def verify(module_name: str, fixed_module: str = None, title: str = None, generate: bool = False):
    """
    Full verification loop:
      1. Run TLC on the base spec
      2. If violated — LLM explains the attack
      3a. generate=False  → run the pre-written fixed spec and confirm
      3b. generate=True   → LLM generates a fix, TLC re-verifies, loops if needed
    """
    display_title = title or module_name
    mode_label = " [🤖 generative mode]" if generate else ""
    banner(f"TLA+ Security Verification Agent\n  Protocol: {display_title}{mode_label}")

    # ── Step 1: Run the base spec ──────────────────────────────────────────────
    result = run_spec(module_name)
    if result is None:
        return

    result_summary(module_name, result.passed, result.states_explored)

    if result.passed:
        ok("Protocol is verified secure — no attacks found.")
        return

    if not result.violation_found:
        fail("TLC finished but result is unclear.")
        print(result.output[:1000])
        return

    fail("Security violation found — protocol is not secure.")

    # ── Step 2: Generative mode — LLM writes + TLC verifies ───────────────────
    if generate:
        generative_loop(module_name, result)
        return

    # ── Step 3: Classic mode — explain then run pre-written fixed spec ─────────
    explain_attack(module_name, result)

    if fixed_module:
        specs_dir  = Path(__file__).parent.parent / "specs"
        fixed_file = specs_dir / f"{fixed_module}.tla"

        if fixed_file.exists():
            section(f"Verifying the fix: {fixed_module}.tla")
            fixed_result = run_spec(fixed_module)

            if fixed_result and fixed_result.passed:
                result_summary(fixed_module, True, fixed_result.states_explored)
                ok("The fix is verified — the attack is no longer possible.")
                _print_comparison(module_name, result, fixed_module, fixed_result)
            elif fixed_result:
                result_summary(fixed_module, False, fixed_result.states_explored)
                fail("Fixed spec still has violations.")
        else:
            info(f"No fixed spec found at specs/{fixed_module}.tla")
            info("Tip: run with --generate to have the LLM create one automatically.")


def _print_comparison(broken: str, broken_result, fixed: str, fixed_result):
    """Print a side-by-side summary of broken vs fixed."""
    section("Summary")
    print(f"  {'Protocol':<35} {'Result':<20} States")
    print(f"  {'─' * 60}")
    states_b = f"{broken_result.states_explored:,}" if broken_result.states_explored else "?"
    states_f = f"{fixed_result.states_explored:,}"  if fixed_result.states_explored  else "?"
    print(f"  {'❌  ' + broken:<35} {'VIOLATED':<20} {states_b}")
    print(f"  {'✅  ' + fixed:<35} {'VERIFIED':<20} {states_f}")
    print()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TLA+ Security Verification Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 main.py --demo insecure              # replay attack on login protocol
              python3 main.py --demo ns                    # Needham-Schroeder MITM attack
              python3 main.py --demo oauth                 # OAuth 2.0 code interception + PKCE fix
              python3 main.py --demo oauth --generate      # LLM generates the PKCE fix live
              python3 main.py --spec MyProto               # run specs/MyProto.tla
              python3 main.py --spec MyProto --generate    # LLM generates a fix for any spec
        """),
    )
    parser.add_argument("--demo",     choices=list(DEMOS.keys()), help="Run a built-in demo")
    parser.add_argument("--spec",     help="Module name of any spec in specs/")
    parser.add_argument("--generate", action="store_true",
                        help="Have the LLM generate a fix and let TLC re-verify it (generative loop)")
    args = parser.parse_args()

    if args.demo:
        d = DEMOS[args.demo]
        verify(
            module_name  = d["module"],
            fixed_module = d.get("fixed_module"),
            title        = f"{d['title']} — {d['description']}",
            generate     = args.generate,
        )
    elif args.spec:
        verify(module_name=args.spec, generate=args.generate)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
