#!/usr/bin/env python3
"""
TLA+ Security Verification Agent
==================================
Uses Claude (claude-opus-4-7) to:
  1. Generate a TLA+ spec for a user-described protocol
  2. Run TLC to model-check it
  3. If a security violation is found, explain the attack
  4. Generate a fixed spec and re-verify
  5. Loop until the protocol is verified secure (or max iterations reached)

Usage:
  python3 main.py                     # interactive mode
  python3 main.py --demo insecure     # run the insecure login demo
  python3 main.py --demo ns           # run the Needham-Schroeder demo
"""

import sys
import os
import argparse
import textwrap
from pathlib import Path

# Make sure we can import sibling modules
sys.path.insert(0, str(Path(__file__).parent))

import llm_client as claude_client
import tlc_runner

# ── Demo protocol descriptions ─────────────────────────────────────────────────

DEMO_PROTOCOLS = {
    "insecure": {
        "name": "InsecureLoginDemo",
        "description": textwrap.dedent("""\
            A basic username/password login protocol where:
            - The client sends username and password in plaintext over the network
            - The server receives the credentials and grants access
            - An attacker can intercept messages on the network
            - An attacker who intercepts credentials can replay them later
            - Model the attacker's ability to intercept and replay messages
            - The SecurityProperty should be: only the real user (not the attacker) can be authenticated
        """),
    },
    "ns": {
        "name": "NeedhamSchroeder",
        "description": textwrap.dedent("""\
            The Needham-Schroeder Public Key Protocol:
            - Initiator A wants to authenticate with Responder B
            - A sends to B: {A, Na} encrypted with B's public key (Na = nonce from A)
            - B sends to A: {Na, Nb} encrypted with A's public key (Nb = nonce from B)
            - A sends to B: {Nb} encrypted with B's public key
            - Model a man-in-the-middle attacker who can intercept and forward messages
            - The SecurityProperty (authentication): if B finishes the protocol thinking
              they are talking to A, then A must have actually initiated with B
            - This protocol has a known flaw: the attacker (E) can use A to help
              attack B by starting a session with A and using A's responses to fool B
        """),
    },
}

# ── Pretty-print helpers ────────────────────────────────────────────────────────

def header(text: str):
    print(f"\n{'═' * 65}")
    print(f"  {text}")
    print(f"{'═' * 65}\n")

def section(text: str):
    print(f"\n{'─' * 65}")
    print(f"  {text}")
    print(f"{'─' * 65}")

def success(text: str):
    print(f"\n✅  {text}")

def failure(text: str):
    print(f"\n❌  {text}")

def info(text: str):
    print(f"ℹ️   {text}")

# ── Core verification loop ──────────────────────────────────────────────────────

def run_verification_loop(protocol_name: str, protocol_description: str, max_iterations: int = 3):
    """
    Main agentic loop:
      - Generate spec → run TLC → if violation → analyze + fix → repeat
    """
    header(f"TLA+ Security Verification Agent")
    info(f"Protocol: {protocol_name}")
    info(f"Max fix iterations: {max_iterations}\n")

    current_spec = None
    current_module = protocol_name

    # ── Step 1: Generate initial spec ─────────────────────────────────────────
    section("Step 1: Generating TLA+ Specification")
    current_spec = claude_client.generate_spec(protocol_description, current_module)

    if not current_spec or len(current_spec) < 50:
        failure("Claude did not return a valid TLA+ spec. Aborting.")
        return

    # Save spec to disk
    tlc_runner.run_tlc_on_content(current_spec, current_module)
    info(f"Spec saved to: tla-specs/{current_module}.tla")

    for iteration in range(max_iterations + 1):
        # ── Step 2: Run TLC ────────────────────────────────────────────────────
        section(f"Step 2: Running TLC Model Checker (iteration {iteration})")
        result = tlc_runner.run_tlc(current_module)

        if result.states_explored:
            info(f"States explored: {result.states_explored:,}")

        if result.error_output and not result.violation_found and not result.passed:
            # TLC itself errored (parse error, etc.)
            failure("TLC encountered an error:")
            print(result.error_output[:2000])
            print("\nFull output:")
            print(result.output[:3000])

            if iteration >= max_iterations:
                failure("Max iterations reached with TLC errors. Please check the spec manually.")
                return

            # Ask Claude to fix syntax/parse errors
            section(f"Step 3 (iter {iteration}): Fixing TLC parse error")
            attack_summary = f"TLC parse/syntax error: {result.error_output[:500]}"
            fixed_spec = claude_client.fix_spec(current_spec, attack_summary, current_module)
            if fixed_spec and len(fixed_spec) > 50:
                current_spec = fixed_spec
                tlc_runner.run_tlc_on_content(current_spec, current_module)
            continue

        if result.passed:
            success(f"TLC verified the protocol — SecurityProperty holds!")
            info(f"The protocol '{current_module}' is secure (no violations found).")
            print(f"\nFinal spec saved at: tla-specs/{current_module}.tla")
            return

        if result.violation_found:
            failure(f"Security violation found in '{current_module}'!")
            if result.counterexample:
                print("\nCounterexample trace:")
                print(result.counterexample[:1500])

            if iteration >= max_iterations:
                failure(f"Could not fix the vulnerability after {max_iterations} attempt(s).")
                info("Try running again or refine the protocol description.")
                return

            # ── Step 3: Analyze the attack ─────────────────────────────────────
            section(f"Step 3 (iter {iteration + 1}): Analyzing the Security Attack")
            analysis = claude_client.analyze_violation(current_spec, result.output)
            attack_summary = claude_client.summarize_attack(analysis)

            # ── Step 4: Generate fixed spec ────────────────────────────────────
            section(f"Step 4 (iter {iteration + 1}): Generating Fixed Protocol")
            # Use the same module name so TLC re-checks it
            fixed_spec = claude_client.fix_spec(current_spec, attack_summary, current_module)

            if not fixed_spec or len(fixed_spec) < 50:
                failure("Claude did not return a valid fixed spec. Stopping.")
                return

            current_spec = fixed_spec
            # Write the fixed spec (overwrite same module for re-checking)
            tlc_runner.run_tlc_on_content(current_spec, current_module)
            info(f"Fixed spec written. Re-running TLC...")
            # Loop continues → TLC re-runs on the fixed spec

        else:
            # Neither passed nor violated — unclear result
            failure("TLC finished but result is unclear. Full output:")
            print(result.output[:2000])
            return

    failure(f"Reached maximum iterations ({max_iterations}) without full verification.")


# ── Interactive mode ────────────────────────────────────────────────────────────

def interactive_mode():
    header("TLA+ Security Verification Agent — Interactive Mode")
    print("Describe a security protocol and I'll generate a TLA+ spec,")
    print("model-check it with TLC, find attacks, and iteratively fix them.\n")

    print("Protocol name (used as TLA+ module name, e.g. MyProtocol):")
    name = input("  > ").strip()
    if not name:
        name = "MyProtocol"
    # Sanitize: TLA+ module names are CamelCase, no spaces
    name = "".join(w.capitalize() for w in name.split())

    print("\nDescribe the protocol (type your description, then press Enter twice):")
    lines = []
    while True:
        line = input()
        if line == "" and lines and lines[-1] == "":
            break
        lines.append(line)
    description = "\n".join(lines).strip()

    if not description:
        print("No description provided. Using insecure login demo.")
        demo = DEMO_PROTOCOLS["insecure"]
        name = demo["name"]
        description = demo["description"]

    run_verification_loop(name, description)


# ── Entry point ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TLA+ Security Verification Agent powered by Claude",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 main.py                     # interactive mode
              python3 main.py --demo insecure     # insecure login + replay attack
              python3 main.py --demo ns           # Needham-Schroeder protocol
        """),
    )
    parser.add_argument(
        "--demo",
        choices=["insecure", "ns"],
        help="Run a built-in demo protocol",
    )
    parser.add_argument(
        "--max-iter",
        type=int,
        default=3,
        help="Maximum fix iterations (default: 3)",
    )
    args = parser.parse_args()

    if args.demo:
        demo = DEMO_PROTOCOLS[args.demo]
        run_verification_loop(demo["name"], demo["description"], max_iterations=args.max_iter)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
