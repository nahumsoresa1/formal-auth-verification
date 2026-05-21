#!/usr/bin/env python3
"""
TLA+ Security Verification Agent
==================================
Automatically verifies security protocols using TLA+ and TLC.

The agent:
  1. Loads a TLA+ spec (pre-written or from specs/ folder)
  2. Runs TLC to exhaustively check all states
  3. If a security violation is found, uses an LLM to explain the attack
  4. Loops until verified or max iterations reached

Usage:
  python3 main.py --demo insecure     # insecure login (replay attack demo)
  python3 main.py --demo ns           # Needham-Schroeder (coming soon)
  python3 main.py --spec MyProtocol   # run TLC on specs/MyProtocol.tla
"""

import sys
import argparse
import textwrap
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import llm_client
import tlc_runner

# ── Built-in demos — point directly at pre-written specs ──────────────────────

DEMOS = {
    "insecure": {
        "module": "InsecureLogin",
        "title":  "Insecure Login Protocol (Replay Attack)",
    },
    "ns": {
        "module": "NeedhamSchroeder",
        "title":  "Needham-Schroeder Protocol (coming soon)",
    },
}

# ── Pretty print helpers ───────────────────────────────────────────────────────

def header(text):
    print(f"\n{'═' * 65}\n  {text}\n{'═' * 65}\n")

def section(text):
    print(f"\n{'─' * 65}\n  {text}\n{'─' * 65}")

def ok(text):
    print(f"\n✅  {text}")

def fail(text):
    print(f"\n❌  {text}")

def info(text):
    print(f"    {text}")

# ── Core verification loop ─────────────────────────────────────────────────────

def verify(module_name: str, title: str, max_iterations: int = 3):
    """
    Main loop:
      run TLC → if violation → LLM explains → loop
    """
    header(f"TLA+ Security Verification Agent\n  Protocol: {title}")

    specs_dir = Path(__file__).parent.parent / "specs"
    spec_file = specs_dir / f"{module_name}.tla"

    if not spec_file.exists():
        fail(f"Spec not found: specs/{module_name}.tla")
        return

    info(f"Spec: specs/{module_name}.tla")

    for iteration in range(max_iterations + 1):

        # ── Run TLC ───────────────────────────────────────────────────────────
        section(f"Running TLC — iteration {iteration + 1}")
        result = tlc_runner.run_tlc(module_name)

        if result.states_explored:
            info(f"States explored: {result.states_explored:,}")

        # ── Parse error in the spec ───────────────────────────────────────────
        if "Parse Error" in result.output or "Parsing or semantic analysis failed" in result.output:
            fail("TLC could not parse the spec — syntax error.")
            print(result.output[:1000])
            return

        # ── Protocol is verified secure ───────────────────────────────────────
        if result.passed:
            ok("TLC verified the protocol — no violations found.")
            info("The security property holds across all reachable states.")
            return

        # ── Violation found — LLM explains ────────────────────────────────────
        if result.violation_found:
            fail("Security violation found!")

            if result.counterexample:
                section("Counterexample Trace")
                print(result.counterexample)

            if iteration >= max_iterations:
                fail(f"Reached max iterations ({max_iterations}).")
                return

            section("LLM Attack Analysis")
            spec_text = spec_file.read_text()
            analysis  = llm_client.analyze_violation(spec_text, result.output)

            # ── If there's a fixed version available, run it next ─────────────
            fixed_module = f"{module_name}Secure"
            fixed_file   = specs_dir / f"{fixed_module}.tla"

            if fixed_file.exists():
                section(f"Running fixed version: specs/{fixed_module}.tla")
                fixed_result = tlc_runner.run_tlc(fixed_module)
                if fixed_result.passed:
                    ok(f"{fixed_module} is verified secure — the fix works.")
                else:
                    fail(f"{fixed_module} still has violations.")
                return

            info("No fixed spec found yet. Add one at specs/{module_name}Secure.tla")
            return

        # ── Unclear result ─────────────────────────────────────────────────────
        fail("TLC finished but result is unclear.")
        print(result.output[:1500])
        return


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TLA+ Security Verification Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 main.py --demo insecure
              python3 main.py --spec InsecureLogin
        """),
    )
    parser.add_argument("--demo",     choices=list(DEMOS.keys()), help="Run a built-in demo")
    parser.add_argument("--spec",     help="Module name of a spec in specs/ folder")
    parser.add_argument("--max-iter", type=int, default=3, help="Max fix iterations (default: 3)")
    args = parser.parse_args()

    if args.demo:
        d = DEMOS[args.demo]
        verify(d["module"], d["title"], max_iterations=args.max_iter)
    elif args.spec:
        verify(args.spec, args.spec, max_iterations=args.max_iter)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
