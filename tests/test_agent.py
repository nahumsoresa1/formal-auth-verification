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


class TestSecureLogin(unittest.TestCase):
    """SecureLogin.tla must pass TLC — no violations."""

    def test_secure_login_passes(self):
        """NoReplay invariant must HOLD in SecureLogin — nonce prevents replay."""
        result = tlc_runner.run_tlc("SecureLogin")
        self.assertTrue(
            result.passed,
            "SecureLogin should be verified secure but TLC found a violation"
        )

    def test_secure_login_no_violation(self):
        """TLC must find zero violations in SecureLogin."""
        result = tlc_runner.run_tlc("SecureLogin")
        self.assertFalse(
            result.violation_found,
            "SecureLogin should have no security violations"
        )

    def test_contrast_insecure_vs_secure(self):
        """InsecureLogin fails, SecureLogin passes — the fix works."""
        insecure = tlc_runner.run_tlc("InsecureLogin")
        secure   = tlc_runner.run_tlc("SecureLogin")
        self.assertTrue(insecure.violation_found, "InsecureLogin should be broken")
        self.assertTrue(secure.passed,            "SecureLogin should be verified")


class TestNeedhamSchroeder(unittest.TestCase):
    """Needham-Schroeder: insecure version violated, fixed version passes."""

    def test_ns_insecure_finds_attack(self):
        """TLC must find Lowe's man-in-the-middle attack in the original protocol."""
        result = tlc_runner.run_tlc("NeedhamSchroeder")
        self.assertTrue(
            result.violation_found,
            "TLC should find the MITM attack in the original NS protocol"
        )

    def test_ns_insecure_has_counterexample(self):
        """The counterexample must reference Alice, Bob, and Eve."""
        result = tlc_runner.run_tlc("NeedhamSchroeder")
        trace = result.counterexample or ""
        self.assertTrue(
            any(name in trace for name in ["Alice", "Bob", "Eve"]),
            "Counterexample should reference protocol principals"
        )

    def test_ns_fixed_passes(self):
        """Lowe's fix must make the Authentication property hold."""
        result = tlc_runner.run_tlc("NeedhamSchroederFixed")
        self.assertTrue(
            result.passed,
            "NeedhamSchroederFixed should be verified secure with Lowe's fix"
        )

    def test_ns_contrast(self):
        """Original NS fails, fixed NS passes — Lowe's fix works."""
        insecure = tlc_runner.run_tlc("NeedhamSchroeder")
        fixed    = tlc_runner.run_tlc("NeedhamSchroederFixed")
        self.assertTrue(insecure.violation_found, "Original NS should be broken")
        self.assertTrue(fixed.passed,             "Fixed NS should be verified")


class TestOAuth2(unittest.TestCase):
    """OAuth 2.0 authorization code interception: insecure version violated, PKCE fixed version passes."""

    def test_oauth2_insecure_finds_violation(self):
        """TLC must find the code interception attack in OAuth2 without PKCE."""
        result = tlc_runner.run_tlc("OAuth2")
        self.assertTrue(
            result.violation_found,
            "TLC should find the authorization code interception attack in OAuth2"
        )

    def test_oauth2_insecure_has_counterexample(self):
        """The counterexample must show attacker obtaining the token."""
        result = tlc_runner.run_tlc("OAuth2")
        trace = result.counterexample or result.output
        self.assertTrue(
            "attacker" in trace.lower(),
            "Counterexample should reference the attacker"
        )

    def test_oauth2_fixed_passes(self):
        """PKCE fix (OAuth2Fixed) must make OnlyClientGetsToken hold."""
        result = tlc_runner.run_tlc("OAuth2Fixed")
        self.assertTrue(
            result.passed,
            "OAuth2Fixed should be verified secure — PKCE prevents code interception"
        )

    def test_oauth2_contrast(self):
        """Original OAuth2 fails, OAuth2Fixed passes — PKCE fix works."""
        insecure = tlc_runner.run_tlc("OAuth2")
        fixed    = tlc_runner.run_tlc("OAuth2Fixed")
        self.assertTrue(insecure.violation_found, "OAuth2 without PKCE should be broken")
        self.assertTrue(fixed.passed,             "OAuth2 with PKCE should be verified")


class TestGenerativeLoop(unittest.TestCase):
    """Generative loop: LLM generates a fix, generate_fix returns valid TLA+ text."""

    def test_generate_fix_returns_tla_text(self):
        """generate_fix() must return a non-empty string containing TLA+ module syntax."""
        result   = tlc_runner.run_tlc("OAuth2")
        spec_dir = Path(__file__).parent.parent / "specs"
        spec_text = (spec_dir / "OAuth2.tla").read_text()

        analysis      = llm_client.analyze_violation(spec_text, result.output)
        attack_summary = llm_client.summarize_attack(analysis)
        generated     = llm_client.generate_fix(spec_text, attack_summary, "OAuth2LLMFixed")

        self.assertIsInstance(generated, str)
        self.assertGreater(len(generated), 100, "Generated spec was too short to be valid TLA+")
        self.assertIn("MODULE", generated, "Generated text does not look like a TLA+ module")

    def test_summarize_attack_returns_short_string(self):
        """summarize_attack() must return a non-empty string under 300 chars."""
        analysis = (
            "This is an authorization code interception attack where the attacker "
            "steals the code from the redirect URL and exchanges it for a token."
        )
        summary = llm_client.summarize_attack(analysis)
        self.assertIsInstance(summary, str)
        self.assertGreater(len(summary), 0)
        self.assertLessEqual(len(summary), 300)


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
