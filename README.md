# Agentic System for Robust Cyber-Security

**CE 356 — Intro. to Formal Spec. and Verification | Northwestern University**

**Team:** Miguel Hernandez · Nahum Soresa

---

## What this is

A Python agent that automatically verifies whether a security protocol is safe.

The agent runs TLC — a formal model checker — to exhaustively explore every possible state of a protocol. If it finds an attack, a local LLM (Ollama) explains what happened in plain English. The agent then verifies the fixed version of the protocol and produces a comparison summary.

**Level 2 — Generative loop:** With `--generate`, the agent goes further. The LLM writes a fixed TLA+ spec from scratch, TLC re-verifies it, and the loop retries automatically (with error feedback) until the invariant holds. No pre-written fix required.

No API key required. Runs entirely on your machine.

---

## How it works

```
User picks a protocol
        ↓
Agent runs TLC — checks every reachable state
        ↓
Attack found?
  → Print the counterexample trace
  → LLM explains the attack in plain English

  Classic mode (default):
  → Run the pre-written fixed spec
  → TLC verifies the fix is secure

  Generative mode (--generate):
  → LLM writes a fixed TLA+ spec
  → TLC verifies it — if still broken, feed error back to LLM
  → Repeat up to 3 iterations until invariant holds
        ↓
No attack found?
  → Protocol is formally verified secure
```

This is not testing — TLC provides a mathematical proof over all possible behaviors.

---

## Protocols

| Protocol | Result | States | Attack |
|---|---|---|---|
| `InsecureLogin` | ❌ Violated | 6 | Replay — attacker reuses captured credentials |
| `SecureLogin` | ✅ Verified | 7 | Nonce-based fix prevents replay |
| `NeedhamSchroeder` | ❌ Violated | 17 | MITM — Eve impersonates Alice to Bob |
| `NeedhamSchroederFixed` | ✅ Verified | 9 | Lowe's 1995 fix: identity in message 2 |
| `OAuth2` | ❌ Violated | 9 | Authorization code interception |
| `OAuth2Fixed` | ✅ Verified | 11 | PKCE (RFC 7636) blocks code theft |

---

## Setup

**1. Install Ollama and pull the model**
```bash
brew install ollama
ollama serve        # start the server
ollama pull llama3.1
```

**2. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**3. Make sure Java is installed** (required for TLC)
```bash
java -version
```

**4. Install the TLA+ extension in VS Code** (provides `tla2tools.jar`)

---

## Run

```bash
cd agent

# Classic mode — pre-written fixes
python3 main.py --demo insecure          # replay attack on login protocol
python3 main.py --demo ns                # Needham-Schroeder MITM attack (1978/1995)
python3 main.py --demo oauth             # OAuth 2.0 code interception + PKCE fix

# Generative mode — LLM writes the fix, TLC re-verifies
python3 main.py --demo oauth --generate  # LLM generates the PKCE fix live
python3 main.py --spec MyProto --generate  # generative loop on any spec
```

## Test

```bash
python3 tests/test_agent.py       # 15 tests — all should pass
```

---

## Project structure

```
├── agent/
│   ├── main.py          # Entry point, demo runner, generative loop
│   ├── llm_client.py    # Ollama interface, TLA+ sanitizer, generate_fix()
│   ├── tlc_runner.py    # TLC subprocess wrapper
│   └── prompts.py       # LLM prompt templates
│
├── specs/
│   ├── InsecureLogin.tla          # Plaintext login — replay attack
│   ├── SecureLogin.tla            # Nonce-based fix — verified secure
│   ├── NeedhamSchroeder.tla       # Original NS protocol — MITM attack
│   ├── NeedhamSchroederFixed.tla  # Lowe's fix — verified secure
│   ├── OAuth2.tla                 # OAuth 2.0 — code interception attack
│   └── OAuth2Fixed.tla            # PKCE fix — verified secure
│
├── tests/
│   └── test_agent.py    # 15 automated tests
│
├── docs/
│   ├── Midterm_Report.md
│   └── Final_Report.md
│
└── requirements.txt
```

---

*Development assisted by [Claude Code](https://claude.ai/code) (Anthropic).*
