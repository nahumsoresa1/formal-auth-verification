"""
Test suite for the TLA+ Security Verification Agent.

Run with:
  python3 tests/test_agent.py

Each test prints PASS or FAIL with a clear reason so you know
exactly what is and isn't working before moving forward.
"""

import sys
import os
import unittest
from pathlib import Path

# Allow imports from agent/
sys.path.insert(0, str(Path(__file__).parent.parent / "agent"))

import tlc_runner
import llm_client


class TestTLCJar(unittest.TestCase):
    """TLC jar can be found on disk."""

    def test_jar_exists(self):
        """The tla2tools.jar file exists at the auto-detected path."""
        self.assertTrue(
            os.path.exists(tlc_runner.TLC_JAR),
            f"TLC jar not found at: {tlc_runner.TLC_JAR}"
        )


class TestTLCRunner(unittest.TestCase):
    """TLC runs correctly and returns the right results."""

    def test_insecure_login_finds_violation(self):
        """InsecureLogin.tla must produce a security violation (replay attack)."""
        result = tlc_runner.run_tlc("InsecureLogin")
        self.assertTrue(
            result.violation_found,
            "Expected TLC to find a violation in InsecureLogin — replay attack should be detected"
        )

    def test_insecure_login_explores_states(self):
        """TLC must explore at least 1 state."""
        result = tlc_runner.run_tlc("InsecureLogin")
        self.assertIsNotNone(result.states_explored)
        self.assertGreater(result.states_explored, 0)

    def test_insecure_login_has_counterexample(self):
        """TLC must produce a counterexample trace when violation is found."""
        result = tlc_runner.run_tlc("InsecureLogin")
        self.assertIsNotNone(
            result.counterexample,
            "Expected a counterexample trace but got None"
        )

    def test_missing_spec_returns_graceful_error(self):
        """Asking TLC to run a non-existent spec should not crash — return error cleanly."""
        result = tlc_runner.run_tlc("ThisSpecDoesNotExist")
        self.assertFalse(result.passed)
        self.assertFalse(result.violation_found)
        self.assertIn("not found", result.error_output.lower())


class TestOllamaConnection(unittest.TestCase):
    """Ollama is running and the model responds."""

    def test_ollama_is_reachable(self):
        """Ollama server must be running and return a response."""
        try:
            import ollama
            response = ollama.chat(
                model="llama3.1",
                messages=[{"role": "user", "content": "Reply with one word: hello"}],
            )
            reply = response["message"]["content"].strip()
            self.assertTrue(len(reply) > 0, "Ollama returned an empty response")
        except Exception as e:
            self.fail(f"Ollama not reachable: {e}\nMake sure 'ollama serve' is running.")

    def test_analyze_violation_returns_text(self):
        """LLM analysis of a TLC trace must return a non-empty string."""
        result = tlc_runner.run_tlc("InsecureLogin")
        self.assertTrue(result.violation_found)

        spec_text = (Path(__file__).parent.parent / "specs" / "InsecureLogin.tla").read_text()
        analysis = llm_client.analyze_violation(spec_text, result.output)

        self.assertIsInstance(analysis, str)
        self.assertGreater(len(analysis), 50, "LLM analysis was too short to be useful")


class TestFullLoop(unittest.TestCase):
    """End-to-end: TLC finds attack, LLM explains it."""

    def test_insecure_login_full_loop(self):
        """Run TLC on InsecureLogin, feed trace to LLM, get explanation."""
        result = tlc_runner.run_tlc("InsecureLogin")

        # TLC must find the violation
        self.assertTrue(result.violation_found)

        # LLM must explain it
        spec_text = (Path(__file__).parent.parent / "specs" / "InsecureLogin.tla").read_text()
        analysis = llm_client.analyze_violation(spec_text, result.output)

        # Response should mention the attack type
        keywords = ["replay", "intercept", "attack", "attacker", "credential"]
        found = any(kw in analysis.lower() for kw in keywords)
        self.assertTrue(
            found,
            f"LLM response did not mention any expected attack keywords.\nGot: {analysis[:300]}"
        )


if __name__ == "__main__":
    # Run with verbose output so each test name is visible
    unittest.main(verbosity=2)
