"""
TLC model checker runner — wraps the TLA+ tools jar.
"""

import subprocess
import tempfile
import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

TLC_JAR = os.path.expanduser(
    "~/.vscode/extensions/tlaplus.vscode-ide-2026.5.81518/tools/tla2tools.jar"
)

SPECS_DIR = Path(__file__).parent.parent / "specs"


@dataclass
class TLCResult:
    passed: bool
    output: str
    error_output: str
    violation_found: bool
    counterexample: Optional[str]
    states_explored: Optional[int]


def _extract_counterexample(output: str) -> Optional[str]:
    """Pull the error trace out of TLC output."""
    lines = output.splitlines()
    trace_start = None
    for i, line in enumerate(lines):
        if "Error: Invariant" in line or "Error: Property" in line or "Invariant" in line and "violated" in line:
            trace_start = i
            break
        if "Error-Trace" in line or "The following behavior constitutes" in line:
            trace_start = i
            break

    if trace_start is None:
        # Try finding state traces
        for i, line in enumerate(lines):
            if re.match(r"^State \d+:", line) or re.match(r"^\d+:", line):
                trace_start = max(0, i - 2)
                break

    if trace_start is not None:
        return "\n".join(lines[trace_start:])
    return None


def _extract_states(output: str) -> Optional[int]:
    """Extract the number of states explored from TLC output."""
    match = re.search(r"(\d[\d,]*) states generated", output)
    if match:
        return int(match.group(1).replace(",", ""))
    return None


def write_spec_to_file(spec_content: str, module_name: str) -> tuple[Path, Path]:
    """Write TLA+ spec and auto-generate a minimal cfg file. Returns (tla_path, cfg_path)."""
    tla_path = SPECS_DIR / f"{module_name}.tla"
    cfg_path = SPECS_DIR / f"{module_name}.cfg"

    tla_path.write_text(spec_content)

    # Auto-generate cfg if it doesn't exist
    if not cfg_path.exists():
        # Try to find an INVARIANT defined in the spec
        invariants = re.findall(r"^(\w+)\s*==\s*", spec_content, re.MULTILINE)
        # Look specifically for SecurityProperty or anything ending in Property/Invariant
        security_props = [i for i in invariants if "SecurityProperty" in i
                          or "Safety" in i or "Invariant" in i or "NoReplay" in i
                          or "NoBadLogin" in i]
        inv_line = f"INVARIANT {security_props[0]}" if security_props else ""

        cfg_content = f"SPECIFICATION Spec\n{inv_line}\nCHECK_DEADLOCK FALSE\n"
        cfg_path.write_text(cfg_content)

    return tla_path, cfg_path


def run_tlc(module_name: str, timeout: int = 60) -> TLCResult:
    """Run TLC on a spec that's already in tla-specs/. Returns a TLCResult."""
    tla_path = SPECS_DIR / f"{module_name}.tla"
    cfg_path = SPECS_DIR / f"{module_name}.cfg"

    if not tla_path.exists():
        return TLCResult(
            passed=False,
            output="",
            error_output=f"Spec file not found: {tla_path}",
            violation_found=False,
            counterexample=None,
            states_explored=None,
        )

    cmd = [
        "java", "-jar", TLC_JAR,
        "-config", str(cfg_path),
        str(tla_path),
        "-workers", "2",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(SPECS_DIR),
        )
        combined_output = result.stdout + result.stderr
        violation = (
            "Error: Invariant" in combined_output
            or "is violated" in combined_output
            or "Invariant violated" in combined_output
            or "Error: Property" in combined_output
            or "Invariant NoReplay" in combined_output
            or "Invariant SecurityProperty" in combined_output
        )
        deadlock = "Deadlock reached" in combined_output
        passed = (
            "Model checking completed" in combined_output
            and not violation
            and not deadlock
        ) or ("No error" in combined_output and not violation and not deadlock)

        return TLCResult(
            passed=passed,
            output=combined_output,
            error_output=result.stderr,
            violation_found=violation,
            counterexample=_extract_counterexample(combined_output) if violation else None,
            states_explored=_extract_states(combined_output),
        )
    except subprocess.TimeoutExpired:
        return TLCResult(
            passed=False,
            output="",
            error_output=f"TLC timed out after {timeout}s",
            violation_found=False,
            counterexample=None,
            states_explored=None,
        )
    except Exception as e:
        return TLCResult(
            passed=False,
            output="",
            error_output=str(e),
            violation_found=False,
            counterexample=None,
            states_explored=None,
        )


def run_tlc_on_content(spec_content: str, module_name: str, cfg_content: Optional[str] = None) -> TLCResult:
    """Write spec to disk and run TLC, returning results. Cleans up temp files."""
    tla_path = SPECS_DIR / f"{module_name}.tla"
    cfg_path = SPECS_DIR / f"{module_name}.cfg"

    tla_path.write_text(spec_content)
    if cfg_content:
        cfg_path.write_text(cfg_content)
    else:
        write_spec_to_file(spec_content, module_name)  # auto-gen cfg

    return run_tlc(module_name)
