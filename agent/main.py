#!/usr/bin/env python3
"""
TLA+ Security Verification Agent
==================================
Automatically verifies security protocols using TLA+ and TLC.

The agent:
  1. Loads a pre-written TLA+ spec from specs/
  2. Runs TLC to exhaustively check all reachable states
  3. If a violation is found, uses a local LLM (Ollama) to explain the attack
  4. If a fixed version exists, runs it and confirms the fix works

Usage:
  python3 main.py --demo insecure     # replay attack on login protocol
  python3 main.py --demo ns           # Needham-Schroeder MITM attack
  python3 main.py --spec MyProtocol   # run any spec in specs/
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
    """Use the LLM to explain the attack from the counterexample."""
    specs_dir = Path(__file__).parent.parent / "specs"
    spec_text  = (specs_dir / f"{module_name}.tla").read_text()

    section("Counterexample — Attack Trace")
    if result.counterexample:
        # Print the trace cleanly, skip the long TLC header lines
        lines = result.counterexample.splitlines()
        for line in lines:
            if line.strip():
                print(f"  {line}")

    section("LLM Attack Analysis")
    llm_client.analyze_violation(spec_text, result.output)


def verify(module_name: str, fixed_module: str = None, title: str = None):
    """
    Full verification loop:
      1. Run TLC on the base spec
      2. If violated — LLM explains the attack
      3. If a fixed spec exists — run it and confirm
    """
    display_title = title or module_name
    banner(f"TLA+ Security Verification Agent\n  Protocol: {display_title}")

    # ── Run base spec ──────────────────────────────────────────────────────────
    result = run_spec(module_name)
    if result is None:
        return

    result_summary(module_name, result.passed, result.states_explored)

    if result.passed:
        ok("Protocol is verified secure — no attacks found.")
        return

    if result.violation_found:
        fail("Security violation found — protocol is not secure.")
        explain_attack(module_name, result)

        # ── Run fixed spec if available ────────────────────────────────────────
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
        return

    fail("TLC finished but result is unclear.")
    print(result.output[:1000])


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
              python3 main.py --demo insecure   # replay attack on login protocol
              python3 main.py --demo ns         # Needham-Schroeder MITM attack
              python3 main.py --spec MyProto    # run specs/MyProto.tla
        """),
    )
    parser.add_argument("--demo", choices=list(DEMOS.keys()), help="Run a built-in demo")
    parser.add_argument("--spec", help="Module name of any spec in specs/")
    args = parser.parse_args()

    if args.demo:
        d = DEMOS[args.demo]
        verify(
            module_name  = d["module"],
            fixed_module = d.get("fixed_module"),
            title        = f"{d['title']} — {d['description']}",
        )
    elif args.spec:
        verify(module_name=args.spec)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
