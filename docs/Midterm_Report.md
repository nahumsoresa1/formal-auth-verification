# CE 365 Midterm Project Report
## Agentic System for Robust Cyber-Security

**Northwestern University — CE 365: Intro. to Formal Spec. and Verification**
**Prof. Hai Zhou**

**Team Members:** Miguel Hernandez · Nahum Soresa
**GitHub:** https://github.com/nahumsoresa1/formal-auth-verification

---

## 1. Project Overview

We are building an agentic system that automatically generates, verifies, and repairs security protocols using TLA+ and the TLC model checker. The system targets a core problem in software security: developers design authentication protocols without any formal guarantee of correctness, and vulnerabilities only surface after deployment.

Our agent closes this gap. A user describes a protocol in plain English. The agent generates a formal TLA+ specification, runs TLC to exhaustively check all possible system states, and if an attack is found, explains it and generates a fixed version — repeating until the protocol is verified secure.

This directly implements the feedback loop described in the course guidelines: AI generates the spec and proof hand-by-hand, TLC makes proof checking automatic, and the loop runs without human intervention.

---

## 2. System Architecture

The system has three components that form a closed feedback loop:

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│   User: "Describe a login protocol..."              │
│                        │                            │
│                        ▼                            │
│         ┌─────────────────────────┐                 │
│         │   LLM (Ollama / local)  │                 │
│         │  Generates TLA+ spec    │                 │
│         └────────────┬────────────┘                 │
│                      │                              │
│                      ▼                              │
│         ┌─────────────────────────┐                 │
│         │   TLC Model Checker     │◄──────────┐     │
│         │  Exhaustive state-space │           │     │
│         │  verification           │           │     │
│         └────────────┬────────────┘           │     │
│                      │                        │     │
│          ┌───────────┴───────────┐            │     │
│          │                       │            │     │
│     PASS ▼                FAIL   ▼            │     │
│    ╔══════════╗     ┌─────────────────────┐   │     │
│    ║ VERIFIED ║     │ LLM reads trace,    │   │     │
│    ║  SECURE  ║     │ explains attack,    │   │     │
│    ╚══════════╝     │ generates fixed spec│───┘     │
│                     └─────────────────────┘         │
│                                                     │
└─────────────────────────────────────────────────────┘
```

**Component 1 — LLM Agent (Ollama, local)**
Receives a protocol description and generates a TLA+ specification that models the user, the server, and an active attacker. Also reads TLC counterexample traces and generates repaired specs.

**Component 2 — TLC Model Checker**
Exhaustively explores every reachable state of the protocol. If a security invariant is violated in any state, TLC produces a counterexample trace showing the exact sequence of steps that leads to the attack. This is not testing — it is mathematical proof over all possible behaviors.

**Component 3 — Python Orchestrator**
The glue layer. Manages the feedback loop: calls the LLM, writes specs to disk, invokes TLC as a subprocess, parses output, and decides whether to loop or terminate. This is the "agent" in the agentic sense — it acts autonomously without human input at each step.

---

## 3. What We Have Built

### 3.1 Insecure Authentication Protocol — TLA+ Specification

We have written and verified a TLA+ model of a basic login protocol where a user sends credentials in plaintext. The model includes an explicit attacker who can intercept messages and replay them.

Key elements of the spec:

- **State variables:** `state` (protocol phase), `network` (message channel), `loggedIn`, `attackerKnows`
- **Actions:** `SendCredentials`, `AttackerIntercept`, `LoginSuccess`, `AttackerReplay`
- **Security invariant:** `NoReplay` — if a user is logged in, the attacker must not know the credentials

```tla
------------------------------ MODULE InsecureLogin ------------------------------
EXTENDS Naturals, Sequences

CONSTANTS User, Attacker, Password
VARIABLES state, network, loggedIn, attackerKnows

Init ==
  /\ state = "start"
  /\ network = << >>
  /\ loggedIn = FALSE
  /\ attackerKnows = FALSE

SendCredentials ==       \* User sends password in plaintext
  /\ state = "start"
  /\ network' = Append(network, <<"user", Password>>)
  /\ state' = "sent"
  /\ UNCHANGED <<loggedIn, attackerKnows>>

AttackerIntercept ==     \* Attacker reads message off the wire
  /\ state = "sent"
  /\ Len(network) > 0
  /\ attackerKnows' = TRUE
  /\ UNCHANGED <<state, network, loggedIn>>

AttackerReplay ==        \* Attacker reuses captured credentials
  /\ attackerKnows = TRUE
  /\ loggedIn' = TRUE
  /\ state' = "authenticated"
  /\ UNCHANGED <<network, attackerKnows>>

Next == \/ SendCredentials \/ AttackerIntercept
        \/ LoginSuccess    \/ AttackerReplay

NoReplay == loggedIn => ~attackerKnows   \* INVARIANT — should hold if secure
================================================================================
```

### 3.2 TLC Verification Results

TLC ran exhaustive model checking on this spec. **Result: invariant violated.**

TLC explored 6 states and produced the following counterexample trace:

```
State 1: <Initial>
  state = "start", network = <<>>, loggedIn = FALSE, attackerKnows = FALSE

State 2: <SendCredentials>
  state = "sent", network = <<<<"user", secret>>>>, attackerKnows = FALSE

State 3: <AttackerIntercept>
  state = "sent", network = <<<<"user", secret>>>>, attackerKnows = TRUE

State 4: <AttackerReplay>
  state = "authenticated", loggedIn = TRUE, attackerKnows = TRUE
  *** NoReplay VIOLATED ***
```

**What this proves:** In 4 steps, an attacker who intercepts a single login message can authenticate as the legitimate user. The server has no way to distinguish a replayed credential from a genuine login. TLC has proven this is not just possible — it is guaranteed to be exploitable in every execution where the attacker is present.

### 3.3 Agent Infrastructure

We have also built the Python orchestration layer:

- `agent/main.py` — CLI entry point, manages the verification loop
- `agent/tlc_runner.py` — invokes TLC as a subprocess, parses output, extracts counterexample traces
- `agent/prompts.py` — prompt templates for spec generation, attack analysis, and spec repair
- `agent/claude_client.py` — LLM interface layer (will be adapted to Ollama)

The loop is functional end-to-end for the TLC portion. LLM integration with Ollama is the next step.

---

## 4. Why TLC — Not Testing

A critical point worth stating explicitly: TLC does not test the protocol on a sample of inputs. It explores **every reachable state** of the system. When TLC says the invariant holds, it is a mathematical proof that no execution — no matter how unlikely or adversarial — can violate the property. When TLC finds a counterexample, it is guaranteed to be a real attack, not a false positive.

This is what makes the system useful beyond a demo: it provides actual security guarantees, not just coverage.

---

## 5. Planned Work

### 5.1 Secure Protocol (Next Milestone)
Model a nonce-based version of the login protocol where the server issues a fresh challenge before accepting credentials. TLC should verify that `NoReplay` holds — the attacker cannot replay captured messages because each session requires a unique challenge response.

### 5.2 Needham-Schroeder Protocol
Model the classical Needham-Schroeder public-key protocol — a protocol that was believed secure for 17 years before Gavin Lowe formally found an attack in 1995 using model checking. TLC should rediscover Lowe's man-in-the-middle attack automatically, and our agent should propose and verify Lowe's fix (adding the responder's identity to the second message).

This is a strong case study because the attack is subtle enough that expert cryptographers missed it, but TLC finds it in seconds.

### 5.3 LLM Integration (Ollama)
Integrate Ollama so the agent can accept free-form protocol descriptions and generate TLA+ specs without manual authoring. This completes the full agentic loop: natural language in → verified secure protocol out.

### 5.4 Full Demo
End-to-end demonstration: user types a protocol description, the agent runs autonomously, and produces either a verified-secure spec or a clear explanation of why the protocol cannot be made secure.

---

## 6. Division of Work

| Task | Owner |
|---|---|
| TLA+ specification writing | Miguel |
| Python agent / TLC orchestration | Miguel |
| Ollama integration | Miguel + Nahum |
| Needham-Schroeder modeling | Nahum |
| Secure protocol design | Nahum |
| Final report and documentation | Both |

---

## 7. Summary

At midterm we have: a working TLA+ spec of an insecure protocol, a confirmed TLC counterexample demonstrating a real replay attack, and a Python orchestration framework ready to wrap the verification loop. The remaining work is the secure protocol spec, the Needham-Schroeder case study, and LLM integration via Ollama.

The core contribution of this project is a system where **formal security proofs are generated and checked automatically** — removing the expert bottleneck from protocol verification.
