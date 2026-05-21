# CE 356 Final Project Report
## Agentic System for Robust Cyber-Security

**Northwestern University — CE 356: Intro. to Formal Spec. and Verification**
**Prof. Hai Zhou**

**Team Members:** Miguel Hernandez · Nahum Soresa
**GitHub:** https://github.com/nahumsoresa1/formal-auth-verification

---

## 1. Project Overview

We built an agentic system that automatically verifies security protocols using TLA+ and the TLC model checker. The system targets a fundamental problem in software security: developers design authentication protocols without formal guarantees of correctness, and vulnerabilities only emerge after deployment — sometimes years later.

Our agent addresses this. A user selects or describes a protocol. The agent runs TLC to exhaustively explore every possible system state, finds attacks if they exist, uses a local language model (Ollama) to explain the attack in plain English, and then verifies a fixed version of the protocol. The entire loop runs autonomously without human intervention at each step.

This implements the feedback loop described in the course guidelines: the agent generates correctness checks hand-by-hand with TLC making proof checking automatic.

### What makes this different from testing

TLC does not sample inputs — it exhaustively explores **every reachable state** of the system. When TLC says an invariant holds, it is a mathematical proof that no execution, however unlikely or adversarial, can violate the property. When TLC finds a counterexample, it is a guaranteed real attack, not a false positive. This is the core value of formal verification over conventional security testing.

---

## 2. System Architecture

The system has three components forming a closed verification loop:

```
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   User selects a protocol (or describes one)                 │
│                          │                                   │
│                          ▼                                   │
│           ┌──────────────────────────┐                       │
│           │   Python Orchestrator    │                       │
│           │   agent/main.py          │                       │
│           └─────────────┬────────────┘                       │
│                         │                                    │
│              ┌──────────┴──────────┐                         │
│              │                     │                         │
│              ▼                     ▼                         │
│   ┌─────────────────┐   ┌─────────────────────┐             │
│   │  TLC Model      │   │  LLM (Ollama)        │             │
│   │  Checker        │   │  llama3.1 local      │             │
│   │  specs/*.tla    │   │  llm_client.py       │             │
│   └────────┬────────┘   └──────────┬──────────┘             │
│            │                       │                         │
│     ┌──────┴──────┐                │                         │
│     │             │                │                         │
│   PASS          FAIL               │                         │
│     │             │                │                         │
│     ▼             └──────────────► │                         │
│  VERIFIED      Attack trace   Explains attack                │
│  SECURE        extracted      in plain English               │
│                               │                              │
│                               ▼                              │
│                        Runs fixed spec                       │
│                        Verifies fix works                    │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

**Python Orchestrator (`agent/main.py`)**
Manages the full loop: loads specs, invokes TLC, parses output, calls the LLM, and produces the final summary. Acts autonomously — no human decision needed between steps.

**TLC Model Checker (`agent/tlc_runner.py`)**
Wraps the `tla2tools.jar` binary as a subprocess. Auto-detects the jar across VS Code extension updates. Parses violation output and extracts counterexample traces for the LLM.

**LLM Interface (`agent/llm_client.py`)**
Sends the spec and TLC trace to a locally running Ollama instance (no API key, no cost). The LLM identifies the attack type, explains each step in plain English, and suggests what class of fix is needed.

---

## 3. Protocols Verified

### 3.1 Insecure Login — Replay Attack

**Protocol:** User sends username and password in plaintext. Server accepts and logs the user in.

**Attacker model:** Passive attacker who can intercept messages and replay them.

**TLA+ spec:** `specs/InsecureLogin.tla`
- State variables: `state`, `network`, `loggedIn`, `attackerKnows`
- Actions: `SendCredentials`, `AttackerIntercept`, `LoginSuccess`, `AttackerReplay`
- Invariant: `NoReplay` — if logged in, the attacker must not know the credentials

**TLC result:** ❌ Invariant violated — 6 states explored

**Counterexample (4 steps):**
```
State 1:  state="start",         loggedIn=FALSE, attackerKnows=FALSE
State 2:  state="sent",          credentials on network, attackerKnows=FALSE
State 3:  state="sent",          attackerKnows=TRUE   ← attacker intercepts
State 4:  state="authenticated", loggedIn=TRUE, attackerKnows=TRUE
          *** NoReplay VIOLATED ***
```

**What TLC proved:** In every possible execution of this protocol where the attacker is present, the attacker can authenticate as the legitimate user. The vulnerability is not just exploitable — it is unavoidable.

---

### 3.2 Secure Login — Nonce-Based Challenge-Response

**Protocol:** Server issues a fresh nonce (challenge) before accepting credentials. Client must include the current nonce in their response. Once the server accepts a nonce, it is permanently marked as used.

**TLA+ spec:** `specs/SecureLogin.tla`
- Added variables: `phase`, `nonceUsed`, `authenticatedBy`
- Key fix: `ServerVerify` requires `~nonceUsed` before accepting credentials, then sets `nonceUsed = TRUE`
- Invariant: `NoReplay` — if logged in, `authenticatedBy = "user"`

**TLC result:** ✅ Invariant holds — 7 states explored, no violations

**Why it works:** `AttackerReplay` requires `~nonceUsed`, but `nonceUsed = TRUE` as soon as the session completes. TLC proves that no state exists where the attacker can successfully replay captured credentials after the nonce is spent.

---

### 3.3 Needham-Schroeder Public Key Protocol — MITM Attack

**Background:** Designed in 1978 by Needham and Schroeder. Believed to be a sound mutual authentication protocol for 17 years. In 1995, Gavin Lowe found a man-in-the-middle attack using automated model checking — a landmark result in formal verification of security protocols.

**Protocol:**
```
1.  A → B : {A, Na}_Kb       Alice sends identity + nonce, encrypted for Bob
2.  B → A : {Na, Nb}_Ka      Bob responds with both nonces, encrypted for Alice
3.  A → B : {Nb}_Kb          Alice confirms by returning Bob's nonce
```

**TLA+ spec:** `specs/NeedhamSchroeder.tla`
- Principals: Alice, Bob, Eve (attacker)
- Nonces: Na (from Alice), Nb (from Bob)
- Actions model each message send, Eve's interceptions, and Eve's forwards
- Invariant: `Authentication` — if Bob completed the protocol, Alice must have initiated with Bob

**TLC result:** ❌ Invariant violated — 17 states explored

**The attack (8-step counterexample):**
```
State 1:  Initial — all parties idle
State 2:  Alice initiates with Eve: sends {Alice, Na} encrypted for Eve
State 3:  Eve decrypts (it's for her), learns Na, forwards to Bob as if from Alice
State 4:  Bob responds to Alice: sends {Na, Nb} encrypted for Alice
State 5:  Eve intercepts and forwards to Alice (cannot decrypt — it's for Alice)
State 6:  Alice sees her own Na, trusts the message, sends {Nb} encrypted for Eve
State 7:  Eve decrypts (it's for her), learns Nb, forwards to Bob encrypted for Bob
State 8:  Bob receives {Nb}, completes protocol — believes he authenticated with Alice
          *** Authentication VIOLATED: bPhase="done", aPartner=Eve (not Bob) ***
```

**What TLC proved:** Bob believes he authenticated with Alice. He did not — Eve was the man in the middle throughout. Alice never initiated a session with Bob. The attack is not a flaw in the encryption — it exploits the fact that message 2 does not declare who sent it.

---

### 3.4 Needham-Schroeder-Lowe — Fixed Protocol

**Lowe's fix (1995):** Add the responder's identity to message 2:
```
2'.  B → A : {Na, Nb, B}_Ka     Bob now includes his own identity ← the fix
```

**Why it works:** When Alice receives message 2', she sees Bob's identity inside the message. Alice checks: does the declared sender match her session partner? She initiated with Eve, so her session partner is Eve — not Bob. The message is rejected. Eve's forwarding chain breaks at step 6. Bob never receives message 3 and never completes the protocol.

**TLA+ spec:** `specs/NeedhamSchroederFixed.tla`
- Single change: `BobResponds` adds `sender |-> Bob` to message 2
- `AliceCompletes` adds `m.sender = aPartner` check before accepting

**TLC result:** ✅ Invariant holds — 9 states explored, no violations

---

## 4. Verification Results Summary

| Protocol | Invariant | TLC Result | States | Attack |
|---|---|---|---|---|
| `InsecureLogin` | `NoReplay` | ❌ Violated | 6 | Replay — attacker reuses captured credentials |
| `SecureLogin` | `NoReplay` | ✅ Verified | 7 | Nonce prevents replay |
| `NeedhamSchroeder` | `Authentication` | ❌ Violated | 17 | MITM — Eve impersonates Alice to Bob |
| `NeedhamSchroederFixed` | `Authentication` | ✅ Verified | 9 | Identity in msg2 blocks the attack |

---

## 5. Agent Demo

The full pipeline runs from the command line with no manual steps between TLC and the LLM:

```bash
# Replay attack demo
python3 agent/main.py --demo insecure

# Needham-Schroeder MITM demo
python3 agent/main.py --demo ns
```

Each demo:
1. Runs TLC on the insecure spec — prints the counterexample trace
2. Sends the trace to Ollama — LLM explains the attack in plain English
3. Runs TLC on the fixed spec — confirms the fix is verified secure
4. Prints a comparison summary

---

## 6. Test Suite

The project includes 15 automated tests covering every critical component:

```bash
python3 tests/test_agent.py
```

| Test Class | Tests | What is covered |
|---|---|---|
| `TestTLCJar` | 1 | TLC jar is findable after VS Code updates |
| `TestTLCRunner` | 4 | Violation detection, state counting, graceful error handling |
| `TestSecureLogin` | 3 | NoReplay holds, contrast with insecure version |
| `TestNeedhamSchroeder` | 4 | MITM attack found, Lowe's fix verified, contrast |
| `TestOllamaConnection` | 2 | Ollama reachable, LLM returns meaningful analysis |
| `TestFullLoop` | 1 | End-to-end: TLC → LLM → correct attack identification |

All 15 tests pass.

---

## 7. Technical Stack

| Component | Technology | Notes |
|---|---|---|
| Formal specification | TLA+ | 4 specs, 2 insecure / 2 secure |
| Model checking | TLC (tla2tools.jar) | Bundled with VS Code TLA+ extension |
| Agent orchestration | Python 3 | Subprocess + output parsing |
| LLM | Ollama / llama3.1 | Runs locally, no API cost |
| Version control | Git / GitHub | `nahumsoresa1/formal-auth-verification` |

---

## 8. Conclusions

This project demonstrates that formal verification can be made accessible through automation. The two key results are:

1. **TLC finds real attacks automatically.** For both the login replay attack and the 17-year-old Needham-Schroeder flaw, TLC produces exact counterexample traces in under one second with no manual guidance.

2. **TLC proves fixes are correct.** Once the nonce-based login and Lowe's NS fix are applied, TLC exhaustively verifies that no attack path exists — not just that we did not find one, but that none can exist.

The agentic loop — run TLC, explain the attack, verify the fix — removes the expert bottleneck from protocol verification. A developer with no background in formal methods can run the agent, read the LLM explanation, and understand exactly what is wrong and why the fix works.

---

## 9. Division of Work

| Task | Owner |
|---|---|
| `InsecureLogin.tla` + `SecureLogin.tla` | Miguel |
| `NeedhamSchroeder.tla` + `NeedhamSchroederFixed.tla` | Nahum |
| Python agent orchestration (`main.py`, `tlc_runner.py`) | Miguel |
| Ollama LLM integration (`llm_client.py`, `prompts.py`) | Miguel |
| Test suite (`tests/test_agent.py`) | Miguel + Nahum|
| Final report and documentation | Both |
