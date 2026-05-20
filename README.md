# Agentic System for Robust Cyber-Security

**CE 356 — Intro. to Formal Spec. and Verification | Northwestern University**
**Team:** Miguel Hernandez · Nahum Soresa

---

## What this is

A Python agent that automatically verifies whether a security protocol is safe.

You describe a protocol. The agent writes a formal TLA+ specification, runs the TLC model checker to exhaustively test every possible system state, and if it finds an attack, it explains what happened and generates a fixed version — looping until the protocol is verified secure.

No API key required. Runs entirely on your machine using [Ollama](https://ollama.com).

---

## How it works

```
You describe a protocol
        ↓
Agent writes a TLA+ spec (via local LLM)
        ↓
TLC checks every possible state
        ↓
Attack found? → Agent explains it, writes a fix, re-verifies
        ↓
No attack found? → Protocol is formally verified secure
```

---

## Project structure

```
├── agent/
│   ├── main.py          # Entry point — run this
│   ├── llm_client.py    # Talks to Ollama (local LLM)
│   ├── tlc_runner.py    # Runs TLC, parses results
│   └── prompts.py       # Prompt templates
│
├── specs/
│   ├── InsecureLogin.tla   # Insecure login protocol (replay attack)
│   └── InsecureLogin.cfg   # TLC model config
│
├── docs/
│   └── midterm_report.md
│
├── requirements.txt
└── README.md
```

---

## Setup

**1. Install Ollama**
```bash
# Download from https://ollama.com/download
# Then pull a model:
ollama pull llama3.1
```

**2. Install Python dependencies**
```bash
pip install -r requirements.txt
```

**3. Make sure you have Java installed** (needed for TLC)
```bash
java -version
```

---

## Run it

```bash
cd agent
python3 main.py --demo insecure     # insecure login demo
python3 main.py                     # interactive mode
```

---

## Current protocols

| Protocol | Status | Attack found |
|---|---|---|
| Insecure Login | ✅ Verified (broken) | Replay attack — attacker intercepts credentials and reuses them |
| Secure Login (nonce-based) | 🔜 In progress | — |
| Needham-Schroeder | 🔜 In progress | — |
