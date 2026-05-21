# Agentic System for Robust Cyber-Security

**CE 356 — Intro. to Formal Spec. and Verification | Northwestern University**

**Team:** Miguel Hernandez · Nahum Soresa

---

## What this is

A Python agent that automatically verifies whether a security protocol is safe.

The agent runs TLC — a formal model checker — to exhaustively explore every possible state of a protocol. If it finds an attack, a local LLM (Ollama) explains what happened in plain English. The agent then verifies the fixed version of the protocol and produces a comparison summary.

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
  → Run the fixed version
  → TLC verifies the fix is secure
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

python3 main.py --demo insecure   # replay attack on login protocol
python3 main.py --demo ns         # Needham-Schroeder MITM attack (1978/1995)
python3 main.py --spec MyProto    # run any spec in specs/
```

## Test

```bash
python3 tests/test_agent.py       # 15 tests — all should pass
```

---

## Project structure

```
├── agent/
│   ├── main.py          # Entry point and demo runner
│   ├── llm_client.py    # Ollama interface (local LLM)
│   ├── tlc_runner.py    # TLC subprocess wrapper
│   └── prompts.py       # LLM prompt templates
│
├── specs/
│   ├── InsecureLogin.tla          # Plaintext login — replay attack
│   ├── SecureLogin.tla            # Nonce-based fix — verified secure
│   ├── NeedhamSchroeder.tla       # Original NS protocol — MITM attack
│   └── NeedhamSchroederFixed.tla  # Lowe's fix — verified secure
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
